use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WnsPayload {
    data: HashMap<String, String>,
}

impl WnsPayload {
    pub fn new(data: HashMap<String, String>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &HashMap<String, String> {
        &self.data
    }
}
