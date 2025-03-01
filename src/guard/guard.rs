use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::config::CONFIG;

pub struct IptablesGuard {
    chain_name: String,
    banned_ips: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    dports: Vec<u16>,
}

impl IptablesGuard {
    pub fn new(chain_name: &str) -> Result<Self, String> {
        let dports = {
            let config = CONFIG.lock().unwrap();
            config.dports.clone()
        };

        let guard = IptablesGuard {
            chain_name: chain_name.to_string(),
            banned_ips: Arc::new(Mutex::new(HashMap::new())),
            dports,
        };

        guard.initialize_chain()?;

        Ok(guard)
    }

    fn initialize_chain(&self) -> Result<(), String> {
        let _ = Command::new("iptables")
            .args(&["-D", "INPUT", "-j", &self.chain_name])
            .output();

        let _ = Command::new("iptables")
            .args(&["-F", &self.chain_name])
            .output();

        let _ = Command::new("iptables")
            .args(&["-X", &self.chain_name])
            .output();

        match Command::new("iptables")
            .args(&["-N", &self.chain_name])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    if !error.contains("Chain already exists") {
                        return Err(format!("{}", error));
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "[ReqGuard] Failed to execute iptables command: {}",
                    e
                ))
            }
        };

        match Command::new("iptables")
            .args(&["-I", "INPUT", "1", "-j", &self.chain_name])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("Failed to add rule to INPUT chain: {}", error));
                }
            }
            Err(e) => {
                return Err(format!(
                    "[ReqGuard] Failed to execute iptables command: {}",
                    e
                ))
            }
        };

        Ok(())
    }

    pub fn ban_ip(&self, ip: &str, expiry: DateTime<Utc>) -> Result<(), String> {
        {
            let banned_ips = self.banned_ips.lock().unwrap();
            if banned_ips.contains_key(ip) {
                return Ok(());
            }
        }

        if !self.dports.is_empty() {
            for &port in &self.dports {
                match Command::new("iptables")
                    .args(&[
                        "-A",
                        &self.chain_name,
                        "-s",
                        ip,
                        "-p",
                        "tcp",
                        "--dport",
                        &port.to_string(),
                        "-j",
                        "DROP",
                    ])
                    .output()
                {
                    Ok(output) => {
                        if !output.status.success() {
                            let error = String::from_utf8_lossy(&output.stderr);
                            return Err(format!(
                                "Failed to ban IP {} on port {}: {}",
                                ip, port, error
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "[ReqGuard] Failed to execute iptables command: {}",
                            e
                        ))
                    }
                };
            }
        } else {
            match Command::new("iptables")
                .args(&["-A", &self.chain_name, "-s", ip, "-j", "DROP"])
                .output()
            {
                Ok(output) => {
                    if !output.status.success() {
                        let error = String::from_utf8_lossy(&output.stderr);
                        return Err(format!("Failed to ban IP {}: {}", ip, error));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "[ReqGuard] Failed to execute iptables command: {}",
                        e
                    ))
                }
            };
        }

        {
            let mut banned_ips = self.banned_ips.lock().unwrap();
            banned_ips.insert(ip.to_string(), expiry);
        }

        Ok(())
    }

    pub fn unban_ip(&self, ip: &str) -> Result<(), String> {
        {
            let mut banned_ips = self.banned_ips.lock().unwrap();
            if !banned_ips.contains_key(ip) {
                return Ok(());
            }
            banned_ips.remove(ip);
        }

        if !self.dports.is_empty() {
            for &port in &self.dports {
                match Command::new("iptables")
                    .args(&[
                        "-D",
                        &self.chain_name,
                        "-s",
                        ip,
                        "-p",
                        "tcp",
                        "--dport",
                        &port.to_string(),
                        "-j",
                        "DROP",
                    ])
                    .output()
                {
                    Ok(output) => {
                        if !output.status.success() {
                            return Err(format!("Failed to unban IP {} on port {}", ip, port));
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "[ReqGuard] Failed to execute iptables command: {}",
                            e
                        ))
                    }
                };
            }
        } else {
            match Command::new("iptables")
                .args(&["-D", &self.chain_name, "-s", ip, "-j", "DROP"])
                .output()
            {
                Ok(output) => {
                    if !output.status.success() {
                        return Err(format!("Failed to unban IP {}", ip));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "[ReqGuard] Failed to execute iptables command: {}",
                        e
                    ))
                }
            };
        }

        Ok(())
    }

    pub fn cleanup_expired_bans(&self) -> Result<Vec<String>, String> {
        let now = Utc::now();
        let mut expired_ips = Vec::new();

        {
            let banned_ips = self.banned_ips.lock().unwrap();
            for (ip, expiry) in banned_ips.iter() {
                if *expiry <= now {
                    expired_ips.push(ip.clone());
                }
            }
        }

        for ip in expired_ips.iter() {
            match self.unban_ip(ip) {
                Ok(_) => (),
                Err(_) => eprintln!("[ReqGuard] Failed to unban IP {}", ip),
            }
        }

        Ok(expired_ips)
    }

    pub fn get_banned_ips(&self) -> HashMap<String, DateTime<Utc>> {
        let banned_ips = self.banned_ips.lock().unwrap();
        banned_ips.clone()
    }

    pub fn cleanup(&self) -> Result<(), String> {
        let _ = Command::new("iptables")
            .args(&["-D", "INPUT", "-j", &self.chain_name])
            .output();

        let _ = Command::new("iptables")
            .args(&["-F", &self.chain_name])
            .output();

        match Command::new("iptables")
            .args(&["-X", &self.chain_name])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("Failed to remove chain: {}", error));
                }
            }
            Err(e) => {
                return Err(format!(
                    "[ReqGuard] Failed to execute iptables command: {}",
                    e
                ))
            }
        };

        Ok(())
    }
    pub fn is_banned(&self, ip: &str) -> bool {
        let now = Utc::now();
        let banned_ips = self.banned_ips.lock().unwrap();

        banned_ips
            .get(ip)
            .map(|expiry| *expiry > now)
            .unwrap_or(false)
    }

    pub fn new_mock() -> Self {
        IptablesGuard {
            chain_name: "MOCK".to_string(),
            banned_ips: Arc::new(Mutex::new(HashMap::new())),
            dports: vec![],
        }
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        if let Err(_) = self.cleanup() {
            eprintln!("[ReqGuard] iptables guard cleanup failed");
        }
    }
}
