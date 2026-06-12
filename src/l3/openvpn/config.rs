use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenVpnConfig {
    pub name: String,
    #[serde(default)]
    pub profile: Option<PathBuf>,
    #[serde(default)]
    pub inline_profile: Option<String>,
    #[serde(default = "default_skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub auth_user_pass: Option<(String, String)>,
}

fn default_skip_cert_verify() -> bool {
    false
}

impl Default for OpenVpnConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            profile: None,
            inline_profile: None,
            skip_cert_verify: default_skip_cert_verify(),
            auth_user_pass: None,
        }
    }
}
