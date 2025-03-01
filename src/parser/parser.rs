use chrono::{DateTime, Utc};

use chrono::NaiveDateTime;
use regex::Regex;

use crate::config::CONFIG;
use crate::models::LogEntry;

pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    let log_regex = {
        let config = CONFIG.lock().unwrap();
        Regex::new(&config.log_regex).unwrap()
    };

    let tokens = log_regex.captures(line)?;
    let timestamp_tok = &tokens["timestamp"];
    let naive_datetime =
        NaiveDateTime::parse_from_str(&timestamp_tok[..26], "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(naive_datetime, Utc);

    let ip = tokens["ip"].to_string();
    let path = tokens["path"].to_string();

    Some(LogEntry {
        timestamp,
        ip,
        path,
    })
}
