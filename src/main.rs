mod controller;
mod parsers;

extern crate clap;
extern crate log;
extern crate pretty_env_logger;

use clap::{Arg, ArgMatches, Command};
use controller::{Search, SearchTrait};

fn run() {
    log::info!("Starting git2mail!");

    let argv: ArgMatches =
        Command::new("git2mail")
            .author("exti0p")
            .about("Pure Rust OSINT tool to find a GitHub user's email")
            .arg(
                Arg::new("url")
                    .short('u')
                    .long("url")
                    .help("GitHub repository or profile URL you want to scan"),
            )
            .arg(
                Arg::new("query")
                    .short('q')
                    .long("query")
                    .help("Query to find interesting GitHub repositories for you"),
            )
            .arg(
                Arg::new("language")
                    .short('l')
                    .long("language")
                    .help("Select a language to enhance your repository searches"),
            )
            .arg(
                Arg::new("limit")
                    .long("limit")
                    .default_value("5")
                    .help("Defines the limit of scanned repositories"),
            )
            .arg(
                Arg::new("token")
                    .short('t')
                    .long("token")
                    .help("Authenticate to the GitHub API with your GitHub token"),
            )
            .arg(Arg::new("token-file").long("token-file").help(
                "JSON file that contains your GitHub tokens to authenticate to the GitHub API",
            ))
            .get_matches();

    let url: String = argv
        .get_one::<String>("url")
        .unwrap_or(&"".to_string())
        .to_string();
    let query: String = argv
        .get_one::<String>("query")
        .unwrap_or(&"".to_string())
        .to_string();

    let mut search = <Search as SearchTrait>::new(
        url.clone(),
        query.clone(),
        argv.get_one::<String>("language")
            .unwrap_or(&"".to_string())
            .to_string(),
        argv.get_one::<String>("token")
            .unwrap_or(&"".to_string())
            .to_string(),
        argv.get_one::<String>("token-file")
            .unwrap_or(&"".to_string())
            .to_string(),
        argv.get_one::<String>("limit")
            .unwrap_or(&"".to_string())
            .parse::<u8>()
            .unwrap_or_default(),
    );

    if !url.is_empty() {
        search.scan_target();
    } else if !query.is_empty() {
        search.aggregate_search();
    }
}

fn main() {
    pretty_env_logger::init();
    run();
}
