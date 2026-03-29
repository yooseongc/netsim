use serde::{Deserialize, Serialize};

use super::netfilter::NfMatch;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct XdpConfig {
    #[serde(default)]
    pub programs: Vec<XdpProgram>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XdpProgram {
    pub interface: String,
    #[serde(default)]
    pub mode: XdpMode,
    #[serde(default)]
    pub rules: Vec<XdpRule>,
    #[serde(default)]
    pub default_action: XdpAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Generic,
    Native,
    Offload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XdpRule {
    #[serde(default)]
    pub matches: Vec<NfMatch>,
    pub action: XdpAction,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum XdpAction {
    #[default]
    Pass,
    Drop,
    Tx,
    Redirect {
        target_if: String,
    },
    Aborted,
}

impl std::fmt::Display for XdpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdpAction::Pass => write!(f, "XDP_PASS"),
            XdpAction::Drop => write!(f, "XDP_DROP"),
            XdpAction::Tx => write!(f, "XDP_TX"),
            XdpAction::Redirect { target_if } => write!(f, "XDP_REDIRECT({})", target_if),
            XdpAction::Aborted => write!(f, "XDP_ABORTED"),
        }
    }
}
