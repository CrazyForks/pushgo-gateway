use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FcmPayload {
    data: HashMap<String, String>,
    priority: &'static str,
}

impl FcmPayload {
    pub fn new(data: HashMap<String, String>, priority: &'static str) -> Self {
        Self { data, priority }
    }

    pub fn priority_for_level(level: Option<&str>) -> &'static str {
        match level.map(|value| value.trim().to_lowercase()) {
            Some(value) if value == "critical" => "HIGH",
            _ => "NORMAL",
        }
    }

    pub fn data(&self) -> &HashMap<String, String> {
        &self.data
    }

    pub fn priority(&self) -> &'static str {
        self.priority
    }
}
