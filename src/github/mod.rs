//! GitHub API access: token pool, HTTP client and the single paginated loop.

pub mod client;
#[cfg(test)]
pub(crate) mod mock;
pub mod paginated;

pub use client::{Client, TokenPool};
pub use paginated::{fetch_paginated, fetch_paginated_with_page_size};
