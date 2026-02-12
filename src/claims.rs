use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub user: String,        // User ID
    pub device: String,        // device ID


    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,     // company id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<i8>,             // Token Type 0:auth, 1:refresh
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<i8>,             // for app 0:mobile, 1:web, 2: backend   

    pub exp: i64,           // Unix timestamp (saniye)
    pub iat: i64,
}

impl Claims {
    pub fn new(user: String, device: String, ttl_seconds: u64) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            user,
            device,

            company: None,
            typ: None,
            app: None,

            iat: now,
            exp: now + ttl_seconds as i64,
        }
    }

    pub fn with_company(mut self, company: String) -> Self {
        self.company = Some(company);
        self
    }
    pub fn with_type(mut self, typ: i8) -> Self {
        self.typ = Some(typ);
        self
    }
    pub fn with_app(mut self, app: i8) -> Self {
        self.app = Some(app);
        self
    }

    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.exp > now && self.iat <= now
    }
}