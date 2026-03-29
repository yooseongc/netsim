use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Failed to parse {kind}: {message}")]
    ParseFailed { kind: String, message: String },

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Unexpected end of input at line {0}")]
    UnexpectedEof(usize),
}
