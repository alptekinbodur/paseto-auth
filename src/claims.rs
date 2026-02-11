use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub user: String,        // User ID
    pub device: String,        // device ID
    pub company: String,
    pub exp: i64,           // Unix timestamp (saniye)
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // Optional
}

impl Claims {
    pub fn new(user: String, company: String, device: String, ttl_seconds: u64) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            user,
            device,
            company,
            iat: now,
            exp: now + ttl_seconds as i64,
            scope: None,
        }
    }

    pub fn with_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.exp > now && self.iat <= now
    }
}