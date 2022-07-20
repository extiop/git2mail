//! OSINT tool to find a GitHub user's email.
//!
//! It uses GitHub repositories metadata regarding commits to get developers' email.
//! It browses a repository and scrapes developers' email through its commits.

/// The `controller` module exists to articulate an user's request and its response
/// For instance, it fetches the GitHub API and if some user token is given, it manages it too.
pub mod controller;

/// The `parsers` module exists to handle some strings and returns requested parts of it
/// For instance, it gets, from a given repository URL, its author and project name.
pub mod parsers;
