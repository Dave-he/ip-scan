use std::fmt;

/// Custom error type for IP scanner
#[derive(Debug)]
#[allow(dead_code)]
pub enum ScanError {
    /// Database operation error
    Database(String),
    /// Network operation error
    Network(String),
    /// Configuration error
    Config(String),
    /// IO error
    Io(std::io::Error),
    /// Parse error
    Parse(String),
    /// Other errors
    Other(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Database(msg) => write!(f, "Database error: {}", msg),
            ScanError::Network(msg) => write!(f, "Network error: {}", msg),
            ScanError::Config(msg) => write!(f, "Configuration error: {}", msg),
            ScanError::Io(err) => write!(f, "IO error: {}", err),
            ScanError::Parse(msg) => write!(f, "Parse error: {}", msg),
            ScanError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::Io(err)
    }
}

impl From<rusqlite::Error> for ScanError {
    fn from(err: rusqlite::Error) -> Self {
        ScanError::Database(err.to_string())
    }
}

impl From<anyhow::Error> for ScanError {
    fn from(err: anyhow::Error) -> Self {
        ScanError::Other(err.to_string())
    }
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, ScanError>;
