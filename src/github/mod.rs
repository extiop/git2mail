//! GitHub API access: token pool, HTTP client and the single paginated loop.

pub mod client;
pub mod paginated;

pub use client::{Client, TokenPool};
pub use paginated::fetch_paginated;
