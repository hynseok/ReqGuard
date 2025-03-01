use serde::Deserialize;
use std::fs;
use std::io;
use std::path::Path;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::load(None)));

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(default = "default_max_duplicate_count")]
    pub max_duplicate_count: usize,

    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: usize,

    #[serde(default = "default_banned_duration_minutes")]
    pub banned_duration_minutes: i64,

    #[serde(default = "default_log_path")]
    pub log_path: String,

    #[serde(default = "default_log_regex")]
    pub log_regex: String,
}

fn default_max_duplicate_count() -> usize {
    10
}

fn default_max_buffer_size() -> usize {
    10
}

fn default_banned_duration_minutes() -> i64 {
    10
}

fn default_log_path() -> String {
    "/var/log/0.log".to_string()
}

fn default_log_regex() -> String {
    r#"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2}) stdout F (?P<ip>\d+\.\d+\.\d+\.\d+) .* \[.*?\] "(?P<method>GET|POST|PUT|DELETE|HEAD) (?P<path>/[^\s]+) HTTP/[\d\.]+""#.to_string()
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load(config_path: Option<&str>) -> Self {
        let default_paths = vec!["config.toml", "/etc/reqguard/config.toml"];

        let paths = if let Some(path) = config_path {
            vec![path]
                .into_iter()
                .chain(default_paths.into_iter())
                .collect()
        } else {
            default_paths
        };

        for path in paths {
            match Self::from_file(path) {
                Ok(config) => {
                    println!("[ReqGuard] Config loaded from {}", path);
                    return config;
                }
                Err(err) => {
                    if let Some(io_err) = err.downcast_ref::<io::Error>() {
                        if io_err.kind() == io::ErrorKind::NotFound {
                            continue;
                        }
                    }
                    eprintln!("[ReqGuard] {} failed to load: {}", path, err);
                }
            }
        }

        eprintln!("[ReqGuard] Falling back to default config");
        Config {
            max_duplicate_count: default_max_duplicate_count(),
            max_buffer_size: default_max_buffer_size(),
            banned_duration_minutes: default_banned_duration_minutes(),
            log_path: default_log_path(),
            log_regex: default_log_regex(),
        }
    }
}
