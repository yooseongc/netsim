use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConntrackState {
    #[default]
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl std::fmt::Display for ConntrackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConntrackState::New => write!(f, "new"),
            ConntrackState::Established => write!(f, "established"),
            ConntrackState::Related => write!(f, "related"),
            ConntrackState::Invalid => write!(f, "invalid"),
            ConntrackState::Untracked => write!(f, "untracked"),
        }
    }
}
