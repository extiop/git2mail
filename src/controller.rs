use crate::parsers;
use itertools::Either;
use lazy_static::lazy_static;
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
    fn aggregate_scan(&mut self, found_repositories: Vec<String>) -> Vec<String>;

    /// Get repositories according to an user request made with metadata.
    ///
    /// For each found repository, it scans it and get its developers emails.
    fn aggregate_search(&mut self);

    /// Creates a custom Search object from given user parameters.
    fn new(
        url: String,
        query: String,
        language: String,
        token: String,
        token_file: String,
        limit: u8,
    ) -> Self;

    /// Fetches a GitHub profile and its events, via GitHub API.
    ///
    /// It gets every events from it, check their metadata to hopefully retrieve his email.
    /// If no email found with profile events, check all user repositories commits.
    /// The latter can lead to retrieve multiple developers emails.
    fn scan_profile(&mut self, author: &str);
    /// Fetches a GitHub repository's commits URLs via GitHub API.
    ///
    /// It uses `parsers` module to extract from a GitHub project URL, its author and its repository.
    /// Then it gets every commit from it, check their metadata to hopefully retrieve some author's email.
    ///
    /// Thus, it can lead to retrieve multiple developers emails.
    fn scan_target(&mut self) -> Either<Vec<String>, ()>;
}

/// Representation of a GitHub search query.
#[derive(Default, Clone)]
pub struct Search {
    pub url: Option<String>,
    pub query: Option<String>,
    pub language: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<String>,
    pub limit: Option<u8>,
    aggregate: bool,
}

impl Search {
    const USER_AGENT_HEADER: &'static str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0";
    const GITHUB_ACCEPT_HEADER: &'static str = "application/vnd.github.v3+json";
}

/// Describes methods for a GitHub search query.
impl SearchTrait for Search {
    /// Concatenate emails found from each repository scanning and sort them.
    fn aggregate_scan(&mut self, found_repositories: Vec<String>) -> Vec<String> {
        let mut found_emails: Vec<String> = Vec::new();

        self.aggregate = true;

        // get found_emails from scan_target function
        for repository_url in found_repositories.iter() {
            self.url = Some(repository_url.to_string());
            let emails: Vec<String> = match self.scan_target().left() {
                Some(emails) => emails,
                _ => panic!("[-] Found emails could not be retrieved"),
            };

            for email in emails.iter() {
                // prevent duplicate emails from different repositories
                if !found_emails.contains(email) {
                    found_emails.push(email.to_string());
                }
            }
        }
        // sort alphabetically found emails
        found_emails.sort_by_key(|a| a.to_lowercase());

        self.aggregate = false;

        found_emails
    }

    /// Get repositories according to an user request made with metadata.
    ///
    /// For each found repository, it scans it and get its developers emails.
    fn aggregate_search(&mut self) {
        let query: &str = match self.query.as_ref() {
            Some(query) => query,
            _ => panic!("[-] Input query is invalid!"),
        };
        let language: &str = match self.language.as_ref() {
            Some(language) => language,
            _ => panic!("[-] Input language is invalid!"),
        };
        let limit: usize = match self.limit {
            Some(limit) => limit.into(),
            _ => panic!("[-] Input limit is invalid!"),
        };

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
        );
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
                process_get_request(client.clone(), (*current_token).to_string(), search_url);

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                let json: serde_json::Value = match response.json::<serde_json::Value>() {
                    Ok(json) => json,
                    _ => panic!("[-] Targeted API response could not be parsed"),
                };

                match json.get("items") {
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
                        println!("[+] Coping with a rate limit: switching to next token!");
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
        let found_emails: Vec<String> = self.clone().aggregate_scan(found_repositories);

        let dir_path: &Path = Path::new("results/keyword");
        let file_name: String = if language.is_empty() {
            query.to_string()
        } else {
            format!("{query}_{language}")
        };
        write_result(dir_path, file_name, found_emails);
    }

    /// Creates a custom Search object from given user parameters.
    fn new(
        url: String,
        query: String,
        language: String,
        token: String,
        token_file: String,
        limit: u8,
    ) -> Self {
        Search {
            url: Some(url),
            query: Some(query),
            language: Some(language),
            token: Some(token),
            token_file: Some(token_file),
            limit: Some(limit),
            aggregate: false,
        }
    }

    /// Fetches a GitHub profile and its events, via GitHub API.
    ///
    /// It gets every events from it, check their metadata to hopefully retrieve his email.
    /// If no email found with profile events, check all user repositories commits.
    /// The latter can lead to retrieve multiple developers emails.
    fn scan_profile(&mut self, author: &str) {
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
        );
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
                process_get_request(client.clone(), (*current_token).to_string(), events_url);

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                let json: serde_json::Value = match response.json::<serde_json::Value>() {
                    Ok(json) => json,
                    _ => panic!("[-] Targeted API response could not be parsed"),
                };

                // check if response is not empty, thus if we reached a page with no more commit
                if format!("{}", json) == "[]" {
                    break;
                }

                for iterator in 0..COMMITS_PER_PAGE {
                    match json.get(iterator as usize) {
                        Some(item) => match item.get("payload") {
                            Some(payload) => match payload.get("commits") {
                                Some(commits) => {
                                    for iterator in 0..COMMITS_PER_PAGE {
                                        match commits.get(iterator as usize) {
                                            Some(commit) => match commit.get("author") {
                                                Some(author) => match author.get("email") {
                                                    Some(email) => {
                                                        // found profile email
                                                        let email =
                                                            email.to_string().replace('"', "");
                                                        // also check that the email is not a noreply email from GitHub or else
                                                        if !email.is_empty()
                                                            && !found_emails.contains(&email)
                                                            && !email.contains("noreply")
                                                        {
                                                            found_emails.push(email);
                                                        }
                                                        break;
                                                    }
                                                    _ => continue,
                                                },
                                                _ => continue,
                                            },
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
                        println!("[+] Coping with a rate limit: switching to next token!");
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
            let found_repositories: Vec<String> = get_author_repositories(
                author,
                self.token.as_ref().unwrap_or(&"".to_string()).to_string(),
                self.token_file
                    .as_ref()
                    .unwrap_or(&"".to_string())
                    .to_string(),
            );
            // for every found repository, scan it and concatenate found emails
            found_emails.append(&mut self.aggregate_scan(found_repositories));
        }
        let dir_path: &Path = Path::new("results/profile");
        let file_name: String = author.to_string();
        write_result(dir_path, file_name, found_emails);
    }

    /// Fetches a GitHub repository's commits URLs via GitHub API.
    /// Fetches also a GitHub profile and its events, still via the latter API.
    ///
    /// It uses `parsers` module to extract from a GitHub project URL, its author and its repository.
    /// Then it gets every commit from it, check their metadata to hopefully retrieve some author's email.
    /// The same process is done with profile events when no repository is specified.
    ///
    /// Thus, regarding repositories, scans can lead to retrieve multiple developers emails.
    fn scan_target(&mut self) -> Either<Vec<String>, ()> {
        // extract from URL author and repository
        let url: &str = match self.url.as_ref() {
            Some(url) => url,
            _ => panic!("[-] Input URL is invalid!"),
        };

        let author: &str = parsers::get_author(url);
        let repository: &str = parsers::get_repository(url);

        // scan profile case, as there is no repository
        if repository.is_empty() {
            // clone might not have the best performance, but it respects the borrow checker
            self.clone().scan_profile(author);
            return itertools::Either::Right(());
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
        );
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
                process_get_request(client.clone(), (*current_token).to_string(), commits_url);

            if response.status().is_success() {
                // for each commit retrieved from previous request, get $i.commit.author.email
                let json: serde_json::Value = match response.json::<serde_json::Value>() {
                    Ok(json) => json,
                    _ => panic!("[-] Targeted API response could not be parsed"),
                };

                // check if response is not empty, thus if we reached a page with no more commit
                if format!("{}", json) == "[]" {
                    break;
                }

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
                        println!("[+] Coping with a rate limit: switching to next token!");
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
        if self.aggregate {
            itertools::Either::Left(found_emails)
        } else {
            let dir_path: &Path = Path::new("results/repository");
            let file_name: String = format!("{author}_{repository}");
            write_result(dir_path, file_name, found_emails);
            itertools::Either::Right(())
        }
    }
}

/// Get all repositories from a GitHub account.
fn get_author_repositories(author: &str, token: String, token_file: String) -> Vec<String> {
    // fetch all repositories log pages via GitHub API
    const REPOSITORIES_PER_PAGE: u8 = 100;
    let mut found_repositories: Vec<String> = Vec::new();
    let client: reqwest::blocking::Client = reqwest::blocking::Client::new();

    // define current token if a single token is specified
    let mut token_counter: u8 = 0;
    let computed_tokens: (Map<String, Value>, String) = get_tokens(token, token_file);
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
        );

        if response.status().is_success() {
            // for each commit retrieved from previous request, get $i.commit.author.email
            let json: serde_json::Value = match response.json::<serde_json::Value>() {
                Ok(json) => json,
                _ => panic!("[-] Targeted API response could not be parsed"),
            };

            // check if response is not empty, thus if we reached a page with no more commit
            if format!("{}", json) == "[]" {
                break;
            }

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
                    println!("[+] Coping with a rate limit: switching to next token!");
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
    found_repositories
}

/// Get a project's root by looking for Cargo.lock file.
fn get_project_root() -> io::Result<PathBuf> {
    let path: PathBuf = env::current_dir()?;
    let path_ancestors = path.as_path().ancestors();

    for path in path_ancestors {
        let has_cargo: bool = read_dir(path)?
            .into_iter()
            .any(|path| match path { Ok(path) => path.file_name(), _ => panic!("Current path could not be handled")} == *OsString::from("Cargo.lock"));
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
fn get_tokens(token: String, token_file: String) -> (Map<String, Value>, String) {
    // define current token if a single token is specified
    let current_token: String;
    let token_counter: u8 = 0;
    let mut tokens: Map<String, Value> = Map::new();

    if !token.is_empty() {
        current_token = token
    } else {
        // parse tokens from token-file if defined
        if !token_file.is_empty() {
            let reader =
                std::fs::read_to_string(token_file).expect("Unable to read JSON token file");
            let parsed: serde_json::Value =
                serde_json::from_str(&reader).expect("Unable to parse JSON token file");
            tokens = match parsed.as_object() {
                Some(tokens) => tokens.clone(),
                _ => panic!("[-] Tokens could not be parsed!"),
            };
            // as token file exists, let's get our first token
            match tokens.get(&token_counter.to_string()) {
                Some(token) => current_token = token.to_string().replace('"', ""),
                _ => panic!("[-] No token provided!"),
            }
        } else {
            // no token provided, default is empty string, leads to limited API access
            current_token = token;
        }
    }
    (tokens, current_token)
}

/// Provides HTTP GET request handling for different cases such as with a token or not.
fn process_get_request(
    client: reqwest::blocking::Client,
    token: String,
    url: String,
) -> reqwest::blocking::Response {
    // following headers are recommended by GitHub API to fetch it nicely
    // if no token is provided, `token` is empty
    if token.is_empty() {
        match client
            .get(url)
            .header(reqwest::header::USER_AGENT, Search::USER_AGENT_HEADER)
            .header(reqwest::header::ACCEPT, Search::GITHUB_ACCEPT_HEADER)
            .send()
        {
            Ok(response) => response,
            _ => panic!("[-] HTTP GET request failed"),
        }
    } else {
        match client
            .get(url)
            .header(reqwest::header::USER_AGENT, Search::USER_AGENT_HEADER)
            .header(reqwest::header::ACCEPT, Search::GITHUB_ACCEPT_HEADER)
            .header(reqwest::header::AUTHORIZATION, format!("token {}", token))
            .send()
        {
            Ok(response) => response,
            _ => panic!("[-] HTTP GET request failed"),
        }
    }
}

/// Keep found results in a file at specific paths according to the user request parameters.
/// Every results is stored in the results directory at the project root.
fn write_result(dir_path: &Path, file_name: String, found_emails: Vec<String>) {
    if !found_emails.is_empty() {
        println!("--------------------------------");
        let length = found_emails.len();
        if length > 1 {
            println!("[+] Found {} emails", length);
        } else {
            println!("[+] Found 1 email");
        }

        lazy_static! {
            // prevent multiple syscall to get pwd
            static ref PROJECT_ROOT: PathBuf = match get_project_root() {
                Ok(path) => path,
                _ => panic!("[-] Couldn't get project root"),
            };
        }

        let file_path: String = format!("{}/{}", dir_path.display(), file_name);
        let absolute_path: String = format!("{}/{}", PROJECT_ROOT.display(), file_path);

        println!("[+] Result is available at {}", absolute_path);

        if let Some(p) = dir_path.to_str() {
            match create_dir_all(p) {
                Ok(path) => path,
                _ => error!("[-] Failed to create directory"),
            }
        };
        let mut file = File::create(absolute_path).expect("Unable to create output file");
        for email in &found_emails {
            let formatted_email: String = format!("{}\n", email);
            file.write_all((*formatted_email).as_bytes())
                .expect("Unable to write data to output file");
        }
    } else {
        println!("[-] No email found");
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
        let mut search = <Search as SearchTrait>::new(
            "".to_string(),
            "Chess.com API".to_string(),
            "Rust".to_string(),
            "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".to_string(),
            "".to_string(),
            1,
        );
        search.aggregate_search();
        let project_root: PathBuf = match get_project_root() {
            Ok(path) => path,
            _ => panic!("[-] Couldn't get project root"),
        };
        let file_path: String = "results/keyword/Chess.com API_Rust".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String = match read_result(absolute_path) {
            Ok(path) => path.trim().to_string(),
            _ => panic!("[-] Couldn't get retrieved email"),
        };
        assert_eq!(found_email, "eli.bp@jottabyte.io");
    }

    #[ignore]
    #[test]
    fn scan_profile() {
        let search = <Search as SearchTrait>::new(
            "https://github.com/anowell".to_string(),
            "".to_string(),
            "".to_string(),
            "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".to_string(),
            "".to_string(),
            1,
        );
        // clone might not have the best performance, but it respects the borrow checker
        search.clone().scan_target();
        let project_root: PathBuf = match get_project_root() {
            Ok(path) => path,
            _ => panic!("[-] Couldn't get project root"),
        };
        let file_path: String = "results/profile/anowell".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String = match read_result(absolute_path) {
            Ok(path) => path.trim().to_string(),
            _ => panic!("[-] Couldn't get retrieved email"),
        };
        assert!(found_email.contains("anowell@gmail.com"));
    }

    #[ignore]
    #[test]
    fn scan_target() {
        let search = <Search as SearchTrait>::new(
            "https://github.com/elibenporat/hikaru".to_string(),
            "".to_string(),
            "".to_string(),
            "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".to_string(),
            "".to_string(),
            1,
        );
        // clone might not have the best performance, but it respects the borrow checker
        search.clone().scan_target();
        let project_root: PathBuf = match get_project_root() {
            Ok(path) => path,
            _ => panic!("[-] Couldn't get project root"),
        };
        let file_path: String = "results/repository/elibenporat_hikaru".to_string();
        let absolute_path: String = format!("{}/{}", project_root.display(), file_path);
        let found_email: String = match read_result(absolute_path) {
            Ok(path) => path.trim().to_string(),
            _ => panic!("[-] Couldn't get retrieved email"),
        };
        assert_eq!(found_email, "eli.bp@jottabyte.io");
    }

    fn read_result(file_path: String) -> Result<String, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(file_path)?;
        Ok(data)
    }
}
