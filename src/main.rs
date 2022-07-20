mod controller;
mod parsers;

extern crate clap;
extern crate log;
extern crate pretty_env_logger;

use clap::{Arg, ArgMatches, Command};
use controller::{Search, SearchTrait};

fn run() {
    log::info!("Starting git2mail!");

    let argv: ArgMatches = Command::new("git2mail")
        .author("exti0p")
        .about("Pure Rust OSINT tool to find a GitHub user's email")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .help("GitHub repository or profile URL you want to scan")
                .takes_value(true),
        )
        .arg(
            Arg::new("query")
                .short('q')
                .long("query")
                .help("Query to find interesting GitHub repositories for you")
                .takes_value(true),
        )
        .arg(
            Arg::new("language")
                .short('l')
                .long("language")
                .help("Select a language to enhance your repository searches")
                .takes_value(true),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .default_value("5")
                .help("Defines the limit of scanned repositories")
                .takes_value(true),
        )
        .arg(
            Arg::new("token")
                .short('t')
                .long("token")
                .help("Authenticate to the GitHub API with your GitHub token")
                .takes_value(true),
        )
        .arg(
            Arg::new("token-file")
                .long("token-file")
                .help(
                    "JSON file that contains your GitHub tokens to authenticate to the GitHub API",
                )
                .takes_value(true),
        )
        .get_matches();

    let mut search = <Search as SearchTrait>::new(
        argv.value_of("url").unwrap_or_default().to_string(),
        argv.value_of("query").unwrap_or_default().to_string(),
        argv.value_of("language").unwrap_or_default().to_string(),
        argv.value_of("token").unwrap_or_default().to_string(),
        argv.value_of("token-file").unwrap_or_default().to_string(),
        argv.value_of("limit")
            .unwrap_or_default()
            .parse::<u8>()
            .unwrap_or_default(),
    );

    if argv.is_present("url") {
        search.scan_target();
    } else if argv.is_present("query") {
        search.aggregate_search();
    }
}

fn main() {
    pretty_env_logger::init();
    run();
}
