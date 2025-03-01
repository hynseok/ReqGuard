use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub path: String,
}
