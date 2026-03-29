use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationReport {
    pub parsed_ok: Vec<String>,
    pub partial: Vec<String>,
    pub unsupported: Vec<String>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_ok(&mut self, msg: impl Into<String>) {
        self.parsed_ok.push(msg.into());
    }

    pub fn add_partial(&mut self, msg: impl Into<String>) {
        self.partial.push(msg.into());
    }

    pub fn add_unsupported(&mut self, msg: impl Into<String>) {
        self.unsupported.push(msg.into());
    }

    pub fn merge(&mut self, other: ValidationReport) {
        self.parsed_ok.extend(other.parsed_ok);
        self.partial.extend(other.partial);
        self.unsupported.extend(other.unsupported);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult<T> {
    pub data: T,
    pub report: ValidationReport,
}
