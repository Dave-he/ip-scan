//! Library surface of the ip-scan crate.
//!
//! `main.rs` is the binary entry point. This `lib.rs` re-exports the
//! pieces other integration tests and downstream tools need, so we can
//! keep `main.rs` thin while still testing the scanner modules from
//! outside the binary.

pub mod api;
pub mod bench;
pub mod cli;
pub mod dao;
pub mod model;
pub mod service;
