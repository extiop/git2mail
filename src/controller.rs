use crate::parsers;
use itertools::Either;
use log::{error, info};
use serde_json::{Map, Value};
use std::ffi::OsString;
use std::fs::{create_dir_all, read_dir, File};
use std::io::{prelude::*, ErrorKind};
use std::path::{Path, PathBuf};
use std::{env, io};

/// Describes types and methods for a GitHub search query.
pub trait SearchTrait {
    /// Concatenate emails found from each repository scanning and sort them.
    fn aggregate_scan(&self, found_repositories: Vec<String>) -> Result<Vec<String>, &str>;

    /// Get repositories according to an user request made with metadata.
    ///
    /// For each found repository, it scans it and get its developers emails.
    fn aggregate_search(&self) -> Result<(), &str>;

    /// Creates a custom Search object from given user parameters.
    fn new(
        query: String,
        language: String,
        token: String,
        token_file: String,
        limit: usize,
    ) -> Self;

    /// Fetches a GitHub profile and its events, via GitHub API.
    ///
    /// It gets every events from it, check their metadata to hopefully retrieve his email.
    /// If no email found with profile events, check all user repositories commits.
    /// The latter can lead to retrieve multiple developers emails.
    fn scan_profile(&self, author: &str) -> Result<(), &str>;
    /// Fetches a GitHub repository's commits URLs via GitHub API.
    ///
    /// It uses `parsers` module to extract from a GitHub project URL, its author and its repository.
    /// Then it gets every commit from it, check their metadata to hopefully retrieve some author's email.
    ///
    /// Thus, it can lead to retrieve multiple developers emails.
    fn scan_target(&self, aggregate: bool, url: String) -> Result<Either<Vec<String>, ()>, &str>;
}

/// Representation of a GitHub search query.
#[derive(Default, Clone)]
pub struct Search {
    pub query: Option<String>,
    pub language: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<String>,
    pub limit: Option<usize>,
}

impl Search {
    const USER_AGENT_HEADER: &'static str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0";
    const GITHUB_ACCEPT_HEADER: &'static str = "application/vnd.github.v3+json";
}

/// Describes methods for a GitHub search query.
impl SearchTrait for Search {
    /// Concatenate emails found from each repository scanning and sort them.
    fn aggregate_scan(&self, found_repositories: Vec<String>) -> Result<Vec<String>, &str> {
        let mut found_emails: Vec<String> = Vec::new();

        // get found_emails from scan_target function
        for repository_url in found_repositories.iter() {
            match self.scan_target(true, repository_url.clone())?.left() {
                Some(emails) => {
                    for email in emails.iter() {
                        // prevent duplicate emails from different repositories
                        if !found_emails.contains(email) {
                            found_emails.push(email.to_string());
                        }
                    }
                }
                _ => return Err("[-] Found emails could not be retrieved"),
            }
        }
        // sort alphabetically found emails
        found_emails.sort_by_key(|a| a.to_lowercase());

        Ok(found_emails)
    }

    /// Get repositories according to an user request made with metadata.
    ///
    /// For each found repository, it scans it and get its developers emails.
    fn aggregate_search(&self) -> Result<(), &str> {
        let query: &str = self.query.as_ref().expect("[-] Input query is invalid!");
        let language: &str = self
            .language
            .as_ref()
            .expect("[-] Input language is invalid!");
        let limit: usize = self.limit.expect("[-] Input limit is invalid!");

        // fetch all repositories pages via GitHub API
        const REPOSITORIES_PER_PAGE: u8 = 100;
        let mut found_repositories: Vec<String> = Vec::new();
        let client: reqwest::blocking::Client = reqwest::blocking::Client::new();

        // define current token if a single token is specified
        let mut token_counter: u8 = 0;
        let computed_tokens: (Map<String, Value>, String) = get_tokens(
            self.token.as_ref().unwrap_or(&"".to_string()).to_string(),
            self.token_file
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string(),
        )?;
        let tokens: Map<String, Value> = computed_tokens.0;
        let mut current_token: String = computed_tokens.1;

        let tokens_length: usize = tokens.len();

        let mut page_number: u16 = 1;
        loop {
            let search_url: String = format!(
                "https://api.github.com/search/repositories?q={}+language:{}&per_page={}&page={}",
                query, language, REPOSITORIES_PER_PAGE, page_number
            );

            let response: reqwest::blocking::Response =
                process_get_request(client.clone(), (*current_token).to_string(), search_url)?;

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                match response.json::<serde_json::Value>() {
                    Ok(json) => {
                        match json.get("items") {
                            // check if response is not empty, thus if we reached a page with no more commit
                            Some(items) if format!("{}", items) == "[]" => break,
                            Some(items) => {
                                for iterator in 0..REPOSITORIES_PER_PAGE {
                                    match items.get(iterator as usize) {
                                        Some(repository) => match repository.get("html_url") {
                                            Some(repository_url) => {
                                                let repository_url =
                                                    repository_url.to_string().replace('"', "");
                                                // check if repository limit is not reached
                                                if found_repositories.len() < limit {
                                                    found_repositories.push(repository_url);
                                                } else {
                                                    break;
                                                }
                                            }
                                            _ => break,
                                        },
                                        _ => break,
                                    }
                                }
                            }
                            _ => break,
                        }
                        Ok(())
                    }
                    _ => Err("[-] Targeted API response could not be parsed"),
                }?;
                page_number += 1;
            } else {
                // authenticated: 5000 req/account/repo/hour
                // non authenticated: 60 req/account/repo/hour
                info!(
                    "Rate limited exceeded. Stopped at commit number {} and page number {}",
                    page_number * REPOSITORIES_PER_PAGE as u16,
                    page_number
                );
                token_counter += 1;

                match tokens.get(&token_counter.to_string()) {
                    Some(token) => {
                        info!("[+] Coping with a rate limit: switching to next token!");
                        current_token = token.to_string().replace('"', "")
                    }
                    _ => {
                        // no more tokens available
                        if token_counter > tokens_length as u8 {
                            error!("[-] No more token available");
                            break;
                        }
                    }
                };
            }
        }
        // for every found repository, scan it and concatenate found emails
        // clone might not have the best performance, but it respects the borrow checker
        let found_emails: Vec<String> = self.aggregate_scan(found_repositories)?;

        let dir_path: &Path = Path::new("results/keyword");
        let file_name: String = if language.is_empty() {
            query.to_string()
        } else {
            format!("{query}_{language}")
        };
        write_result(dir_path, file_name, found_emails)?;
        Ok(())
    }

    /// Creates a custom Search object from given user parameters.
    fn new(
        query: String,
        language: String,
        token: String,
        token_file: String,
        limit: usize,
    ) -> Self {
        Search {
            query: Some(query),
            language: Some(language),
            token: Some(token),
            token_file: Some(token_file),
            limit: Some(limit),
        }
    }

    /// Fetches a GitHub profile and its events, via GitHub API.
    ///
    /// It gets every events from it, check their metadata to hopefully retrieve his email.
    /// If no email found with profile events, check all user repositories commits.
    /// The latter can lead to retrieve multiple developers emails.
    fn scan_profile(&self, author: &str) -> Result<(), &str> {
        // fetch all commits log pages via GitHub API
        const COMMITS_PER_PAGE: u8 = 100;
        let mut found_emails: Vec<String> = Vec::new();
        let client: reqwest::blocking::Client = reqwest::blocking::Client::new();

        // define current token if a single token is specified
        let mut token_counter: u8 = 0;
        let computed_tokens: (Map<String, Value>, String) = get_tokens(
            self.token.as_ref().unwrap_or(&"".to_string()).to_string(),
            self.token_file
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string(),
        )?;
        let tokens: Map<String, Value> = computed_tokens.0;
        let mut current_token: String = computed_tokens.1;

        let tokens_length: usize = tokens.len();

        let mut page_number: u16 = 1;
        loop {
            let events_url: String = format!(
                "https://api.github.com/users/{}/events?per_page={}&page={}",
                author, COMMITS_PER_PAGE, page_number
            );

            let response: reqwest::blocking::Response =
                process_get_request(client.clone(), (*current_token).to_string(), events_url)?;

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                match response.json::<serde_json::Value>() {
                    Ok(json) => {
                        // check if response is not empty, thus if we reached a page with no more commit
                        if format!("{}", json) == "[]" {
                            break;
                        };
                        for iterator in 0..COMMITS_PER_PAGE {
                            match json.get(iterator as usize) {
                                Some(item) => match item.get("payload") {
                                    Some(payload) => match payload.get("commits") {
                                        Some(commits) => {
                                            for iterator in 0..COMMITS_PER_PAGE {
                                                match commits.get(iterator as usize) {
                                                    Some(commit) => {
                                                        match commit.get("author") {
                                                            Some(author) => {
                                                                match author.get("email") {
                                                                    Some(email) => {
                                                                        // found profile email
                                                                        let email = email
                                                                            .to_string()
                                                                            .replace('"', "");
                                                                        // also check that the email is not a noreply email from GitHub or else
                                                                        if !email.is_empty()
                                                                            && !found_emails
                                                                                .contains(&email)
                                                                            && !email
                                                                                .contains("noreply")
                                                                        {
                                                                            found_emails
                                                                                .push(email);
                                                                        }
                                                                        break;
                                                                    }
                                                                    _ => continue,
                                                                }
                                                            }
                                                            _ => continue,
                                                        }
                                                    }
                                                    _ => continue,
                                                }
                                            }
                                        }
                                        _ => continue,
                                    },
                                    _ => continue,
                                },
                                _ => continue,
                            }
                        }
                        Ok(())
                    }
                    _ => Err("[-] Targeted API response could not be parsed"),
                }?;
                page_number += 1;
            } else {
                // authenticated: 5000 req/account/repo/hour
                // non authenticated : 60 req/account/repo/hour
                info!(
                    "Rate limited exceeded. Stopped at commit number {} and page number {}",
                    page_number * COMMITS_PER_PAGE as u16,
                    page_number
                );
                token_counter += 1;

                match tokens.get(&token_counter.to_string()) {
                    Some(token) => {
                        info!("[+] Coping with a rate limit: switching to next token!");
                        current_token = token.to_string().replace('"', "")
                    }
                    _ => {
                        if token_counter > tokens_length as u8 {
                            // no more tokens available
                            error!("[-] No more token available");
                            break;
                        }
                    }
                };
            }
        }
        // if no email found with profile events, check all user repositories commits
        if found_emails.is_empty() {
            match get_author_repositories(
                author,
                self.token.as_ref().unwrap_or(&"".to_string()).to_string(),
                self.token_file
                    .as_ref()
                    .unwrap_or(&"".to_string())
                    .to_string(),
            ) {
                Ok(found_repositories) => {
                    // for every found repository, scan it and concatenate found emails
                    found_emails.append(&mut self.aggregate_scan(found_repositories)?)
                }
                _ => return Err("Could not find repositories"),
            }
        }
        let dir_path: &Path = Path::new("results/profile");
        let file_name: String = author.to_string();
        write_result(dir_path, file_name, found_emails)?;
        Ok(())
    }

    /// Fetches a GitHub repository's commits URLs via GitHub API.
    /// Fetches also a GitHub profile and its events, still via the latter API.
    ///
    /// It uses `parsers` module to extract from a GitHub project URL, its author and its repository.
    /// Then it gets every commit from it, check their metadata to hopefully retrieve some author's email.
    /// The same process is done with profile events when no repository is specified.
    ///
    /// Thus, regarding repositories, scans can lead to retrieve multiple developers emails.
    fn scan_target(&self, aggregate: bool, url: String) -> Result<Either<Vec<String>, ()>, &str> {
        // extract from URL author and repository

        let author: String = parsers::get_author(url.clone())?;
        let repository: String = parsers::get_repository(url)?;

        // scan profile case, as there is no repository
        if repository.is_empty() {
            // clone might not have the best performance, but it respects the borrow checker
            self.scan_profile(author.as_str())?;
            return Ok(itertools::Either::Right(()));
        }

        // fetch all commits log pages via GitHub API
        const COMMITS_PER_PAGE: u8 = 100;
        let mut found_emails: Vec<String> = Vec::new();
        let client: reqwest::blocking::Client = reqwest::blocking::Client::new();

        // define current token if a single token is specified
        let mut token_counter: u8 = 0;
        let computed_tokens: (Map<String, Value>, String) = get_tokens(
            self.token.as_ref().unwrap_or(&"".to_string()).to_string(),
            self.token_file
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string(),
        )?;
        let tokens: Map<String, Value> = computed_tokens.0;
        let mut current_token: String = computed_tokens.1;

        let tokens_length: usize = tokens.len();

        let mut page_number: u16 = 1;
        loop {
            let commits_url: String = format!(
                "https://api.github.com/repos/{}/{}/commits?per_page={}&page={}",
                author, repository, COMMITS_PER_PAGE, page_number
            );

            let response: reqwest::blocking::Response =
                process_get_request(client.clone(), (*current_token).to_string(), commits_url)?;

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                match response.json::<serde_json::Value>() {
                    Ok(json) => {
                        // check if response is not empty, thus if we reached a page with no more commit
                        if format!("{}", json) == "[]" {
                            break;
                        };
                        for iterator in 0..COMMITS_PER_PAGE {
                            match json.get(iterator as usize) {
                                Some(item) => match item.get("commit") {
                                    Some(commit) => match commit.get("author") {
                                        Some(author) => match author.get("email") {
                                            Some(email) => {
                                                let email = email.to_string().replace('"', "");
                                                // also check that the email is not a noreply email from GitHub or else
                                                if !email.is_empty()
                                                    && !found_emails.contains(&email)
                                                    && !email.contains("noreply")
                                                {
                                                    found_emails.push(email);
                                                }
                                            }
                                            _ => break,
                                        },
                                        _ => break,
                                    },
                                    _ => break,
                                },
                                _ => break,
                            }
                        }
                        Ok(())
                    }
                    _ => Err("[-] Targeted API response could not be parsed"),
                }?;
                page_number += 1;
            } else {
                // authenticated: 5000 req/account/repo/hour
                // non authenticated : 60 req/account/repo/hour
                info!(
                    "Rate limited exceeded. Stopped at commit number {} and page number {}",
                    page_number * COMMITS_PER_PAGE as u16,
                    page_number
                );
                token_counter += 1;

                match tokens.get(&token_counter.to_string()) {
                    Some(token) => {
                        info!("[+] Coping with a rate limit: switching to next token!");
                        current_token = token.to_string().replace('"', "")
                    }
                    _ => {
                        if token_counter > tokens_length as u8 {
                            // no more tokens available
                            error!("[-] No more token available");
                            break;
                        }
                    }
                };
            }
        }

        // sort alphabetically found emails
        found_emails.sort_by_key(|a| a.to_lowercase());

        // if function is called by aggregate search
        if aggregate {
            Ok(itertools::Either::Left(found_emails))
        } else {
            let dir_path: &Path = Path::new("results/repository");
            let file_name: String = format!("{author}_{repository}");
            write_result(dir_path, file_name, found_emails)?;
            Ok(itertools::Either::Right(()))
        }
    }
}

/// Get all repositories from a GitHub account.
fn get_author_repositories(
    author: &str,
    token: String,
    token_file: String,
) -> Result<Vec<String>, &str> {
    // fetch all repositories log pages via GitHub API
    const REPOSITORIES_PER_PAGE: u8 = 100;
    let mut found_repositories: Vec<String> = Vec::new();
    let client: reqwest::blocking::Client = reqwest::blocking::Client::new();

    // define current token if a single token is specified
    let mut token_counter: u8 = 0;
    let computed_tokens: (Map<String, Value>, String) = get_tokens(token, token_file)?;
    let tokens: Map<String, Value> = computed_tokens.0;
    let mut current_token: String = computed_tokens.1;

    let tokens_length: usize = tokens.len();

    let mut page_number: u16 = 1;
    loop {
        let repositories_url: String = format!(
            "https://api.github.com/users/{}/repos?per_page={}&page={}",
            author, REPOSITORIES_PER_PAGE, page_number
        );

        let response: reqwest::blocking::Response = process_get_request(
            client.clone(),
            (*current_token).to_string(),
            repositories_url,
        )?;

        if response.status().is_success() {
            // for each commit retrieved from previous request, get $i.commit.author.email
            match response.json::<serde_json::Value>() {
                Ok(json) => {
                    // check if response is not empty, thus if we reached a page with no more commit
                    if format!("{}", json) == "[]" {
                        break;
                    };
                    for iterator in 0..REPOSITORIES_PER_PAGE {
                        match json.get(iterator as usize) {
                            Some(item) => match item.get("html_url") {
                                Some(html_url) => {
                                    // found an user repository
                                    let repository = html_url.to_string().replace('"', "");
                                    if !repository.is_empty() {
                                        found_repositories.push(repository);
                                    }
                                }
                                _ => continue,
                            },
                            _ => continue,
                        }
                    }
                    Ok(())
                }
                _ => Err("[-] Targeted API response could not be parsed"),
            }?;
            page_number += 1;
        } else {
            // authenticated: 5000 req/account/repo/hour
            // non authenticated : 60 req/account/repo/hour
            info!(
                "Rate limited exceeded. Stopped at commit number {} and page number {}",
                page_number * REPOSITORIES_PER_PAGE as u16,
                page_number
            );
            token_counter += 1;

            match tokens.get(&token_counter.to_string()) {
                Some(token) => {
                    info!("[+] Coping with a rate limit: switching to next token!");
                    current_token = token.to_string().replace('"', "")
                }
                _ => {
                    if token_counter > tokens_length as u8 {
                        // no more tokens available
                        error!("[-] No more token available");
                        break;
                    }
                }
            };
        }
    }
    Ok(found_repositories)
}

/// Get a project's root by looking for Cargo.lock file.
fn get_project_root() -> io::Result<PathBuf> {
    let path: PathBuf = env::current_dir()?;
    let path_ancestors = path.as_path().ancestors();

    for path in path_ancestors {
        let has_cargo: bool = read_dir(path)?
            .into_iter()
            .any(|path| match path {
                Ok(path) => Ok(path.file_name()),
                _ => Err("Current path could not be handled")
            } == Ok(OsString::from("Cargo.lock")));
        if has_cargo {
            return Ok(PathBuf::from(path));
        }
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "Ran out of places to find Cargo.toml",
    ))
}

/// Retrieve tokens from a JSON token file.
/// Format should follow an array of indexes and their value is a GitHub API token.
/// `tokens.example.json` at the project root is a correct example.
fn get_tokens<'a>(
    token: String,
    token_file: String,
) -> Result<(Map<String, Value>, String), &'a str> {
    // define current token if a single token is specified
    let current_token: String;
    let token_counter: u8 = 0;
    let tokens: Map<String, Value> = Map::new();

    if !token.is_empty() {
        current_token = token
    } else {
        // parse tokens from token-file if defined
        if !token_file.is_empty() {
            match std::fs::read_to_string(token_file) {
                Ok(reader) => {
                    match serde_json::from_str::<serde_json::Value>(&reader) {
                        Ok(parsed) => {
                            match parsed.as_object() {
                                Some(parsed_tokens) => {
                                    // as token file exists, let's get our first token
                                    match parsed_tokens.get(&token_counter.to_string()) {
                                        Some(token) => {
                                            current_token = token.to_string().replace('"', "");
                                            return Ok((parsed_tokens.clone(), current_token));
                                        }
                                        _ => return Err("[-] No token provided!"),
                                    }
                                }
                                _ => return Err("[-] Tokens could not be parsed!"),
                            }
                        }
                        _ => return Err("Unable to parse JSON token file"),
                    }
                }
                _ => return Err("Unable to read JSON token file"),
            }
        } else {
            // no token provided, default is empty string, leads to limited API access
            current_token = token
        }
    }
    // default token case
    Ok((tokens, current_token))
}

/// Provides HTTP GET request handling for different cases such as with a token or not.
fn process_get_request<'a>(
    client: reqwest::blocking::Client,
    token: String,
    url: String,
) -> Result<reqwest::blocking::Response, &'a str> {
    // following headers are recommended by GitHub API to fetch it nicely
    // if no token is provided, `token` is empty
    if token.is_empty() {
        match client
            .get(url)
            .header(reqwest::header::USER_AGENT, Search::USER_AGENT_HEADER)
            .header(reqwest::header::ACCEPT, Search::GITHUB_ACCEPT_HEADER)
            .send()
        {
            Ok(response) => Ok(response),
            _ => Err("[-] HTTP GET request failed"),
        }
    } else {
        match client
            .get(url)
            .header(reqwest::header::USER_AGENT, Search::USER_AGENT_HEADER)
            .header(reqwest::header::ACCEPT, Search::GITHUB_ACCEPT_HEADER)
            .header(reqwest::header::AUTHORIZATION, format!("token {}", token))
            .send()
        {
            Ok(response) => Ok(response),
            _ => Err("[-] HTTP GET request failed"),
        }
    }
}

/// Keep found results in a file at specific paths according to the user request parameters.
/// Every results is stored in the results directory at the project root.
fn write_result(
    dir_path: &Path,
    file_name: String,
    found_emails: Vec<String>,
) -> Result<PathBuf, &str> {
    if !found_emails.is_empty() {
        info!("--------------------------------");
        let length = found_emails.len();
        if length > 1 {
            info!("[+] Found {} emails", length);
        } else {
            info!("[+] Found 1 email");
        }

        match get_project_root() {
            Ok(project_root) => {
                let dir_absolute_path: String =
                    format!("{}/{}", project_root.display(), dir_path.display());
                let absolute_path: String = format!("{}/{}", dir_absolute_path, file_name);

                info!("[+] Result is available at {}", absolute_path);

                if let Some(p) = Path::new(&dir_absolute_path).to_str() {
                    create_dir_all(p).expect("[-] Failed to create directory")
                };

                let mut file =
                    File::create(absolute_path).expect("[-] Unable to create output file");
                for email in &found_emails {
                    let formatted_email: String = format!("{}\n", email);
                    file.write_all((*formatted_email).as_bytes())
                        .expect("[-] Unable to write data to output file");
                }
                Ok(project_root)
            }
            _ => match env::current_dir() {
                Ok(path) => Ok(path),
                _ => Err("[-] Couldn't get project root"),
            },
        }
    } else {
        Err("[-] No email found")
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    use std::fs;

    // following tests are not working on CI/CD as it can't interact with CI/CD filesystem

    #[ignore]
    #[test]
    fn aggregate_search() {
        let search = <Search as SearchTrait>::new(
            "Chess.com API".to_string(),
            "Rust".to_string(),
            "".to_string(),
            "".to_string(),
            1,
        );
        search
            .aggregate_search()
            .expect("[-] Aggregate search failed");
        let project_root: PathBuf = get_project_root().expect("[-] Couldn't get project root");
        let file_path: String = "results/keyword/Chess.com API_Rust".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String =
            read_result(absolute_path).expect("[-] Couldn't get retrieved email");
        assert_eq!(found_email, "eli.bp@jottabyte.io\n");
    }

    #[ignore]
    #[test]
    fn scan_profile() {
        let search = <Search as SearchTrait>::new(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            1,
        );
        // clone might not have the best performance, but it respects the borrow checker
        search
            .clone()
            .scan_target(false, "https://github.com/anowell".to_string())
            .expect("[-] Target scan failed");
        let project_root: PathBuf = get_project_root().expect("[-] Couldn't get project root");
        let file_path: String = "results/profile/anowell".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String =
            read_result(absolute_path).expect("[-] Couldn't get retrieved email");
        assert!(found_email.contains("anowell@gmail.com"));
    }

    #[ignore]
    #[test]
    fn scan_target() {
        let search = <Search as SearchTrait>::new(
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            1,
        );
        // clone might not have the best performance, but it respects the borrow checker
        search
            .clone()
            .scan_target(false, "https://github.com/elibenporat/hikaru".to_string())
            .expect("[-] Target scan failed");
        let project_root: PathBuf = get_project_root().expect("[-] Couldn't get project root");
        let file_path: String = "results/repository/elibenporat_hikaru".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String =
            read_result(absolute_path).expect("[-] Couldn't get retrieved email");
        assert_eq!(found_email, "eli.bp@jottabyte.io\n");
    }

    fn read_result(file_path: String) -> Result<String, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(file_path)?;
        Ok(data)
    }
}
