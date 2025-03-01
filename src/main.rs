use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::Path,
    sync::mpsc::{channel, RecvTimeoutError},
    time::{Duration as StdDuration, Instant},
};

use chrono::Utc;
use notify::{RecursiveMode, Watcher};
use req_guard::{config::CONFIG, guard::IptablesGuard, models::LogEntry, parser::parse_log_line};

fn main() {
    let (max_buffer_size, max_duplicate_count, banned_duration_minutes, log_path) = {
        let config = CONFIG.lock().unwrap();
        (
            config.max_buffer_size,
            config.max_duplicate_count,
            config.banned_duration_minutes,
            config.log_path.clone(),
        )
    };

    let mut log_buf: VecDeque<LogEntry> = VecDeque::with_capacity(max_buffer_size);
    let banned_duration = chrono::Duration::minutes(banned_duration_minutes);

    let mut last_cleanup = Instant::now();
    let cleanup_interval = StdDuration::from_secs(60);

    let mut request_counts: HashMap<(String, String), usize> = HashMap::new();

    let guard = match IptablesGuard::new("REQGUARD") {
        Ok(g) => {
            println!("[ReqGuard] Successfully initialized iptables guard");
            g
        }
        Err(e) => {
            eprintln!("[ReqGuard] Failed to initialize iptables guard");
            eprintln!("{}", e);
            eprintln!("[ReqGuard] Continuing without IP banning capability");
            IptablesGuard::new_mock()
        }
    };

    let mut last_position: u64 = match File::open(&log_path) {
        Ok(file) => match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(e) => {
                eprintln!("[ReqGuard] Failed to get file metadata: {}", e);
                0
            }
        },
        Err(e) => {
            eprintln!("[ReqGuard] Failed to open log file at startup: {}", e);
            0
        }
    };

    // signal handler for graceful shutdown
    let (stx, srx) = channel();
    ctrlc::set_handler(move || {
        println!("[ReqGuard] Shutting down");
        let _ = stx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    // file system watcher (notifier based on OS)
    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(tx).expect("[ReqGuard] Failed to create watcher");
    watcher
        .watch(Path::new(&log_path), RecursiveMode::NonRecursive)
        .expect("[ReqGuard] Failed to watch log file");

    loop {
        if let Ok(_) = srx.try_recv() {
            break;
        }

        match rx.recv_timeout(StdDuration::from_secs(1)) {
            Ok(_) => {
                let mut file = match File::open(log_path.clone()) {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("[ReqGuard] Failed to open log file: {}", e);
                        continue;
                    }
                };

                let file_size = match file.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(e) => {
                        eprintln!("[ReqGuard] Failed to get file size: {}", e);
                        continue;
                    }
                };

                if file_size < last_position {
                    println!("[ReqGuard] File was truncated or rotated, reading from beginning");
                    last_position = 0;
                }

                if file_size == last_position {
                    continue;
                }

                if let Err(e) = file.seek(SeekFrom::Start(last_position)) {
                    eprintln!(
                        "[ReqGuard] Failed to seek to position {}: {}",
                        last_position, e
                    );
                    continue;
                }

                let mut reader = BufReader::with_capacity(16384, file);
                let mut buffer = Vec::with_capacity(1024);

                while let Ok(bytes_read) = reader.read_until(b'\n', &mut buffer) {
                    if bytes_read == 0 {
                        break;
                    }
                    last_position += bytes_read as u64;

                    if buffer.ends_with(&[b'\n']) {
                        buffer.pop();
                        if buffer.ends_with(&[b'\r']) {
                            buffer.pop();
                        }
                    }

                    if buffer.is_empty() {
                        continue;
                    }

                    let line = match String::from_utf8(std::mem::take(&mut buffer)) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[ReqGuard] Invalid UTF-8 sequence: {}", e);
                            buffer = Vec::with_capacity(1024);
                            continue;
                        }
                    };

                    let now = Utc::now();
                    if last_cleanup.elapsed() >= cleanup_interval {
                        match guard.cleanup_expired_bans() {
                            Ok(expired_ips) => {
                                for ip in expired_ips {
                                    println!("[ReqGuard] {} is no longer banned", ip);
                                }
                            }
                            Err(e) => eprintln!("[ReqGuard] Failed to cleanup expired bans: {}", e),
                        }

                        last_cleanup = Instant::now();
                    }

                    if let Some(entry) = parse_log_line(&line) {
                        if guard.is_banned(&entry.ip) {
                            println!("[ReqGuard] {} is banned", entry.ip);
                            buffer = Vec::with_capacity(1024);
                            continue;
                        }

                        log_buf.push_back(entry.clone());
                        if log_buf.len() > max_buffer_size {
                            log_buf.pop_front();
                            clean_request_counts(&log_buf, &mut request_counts);
                        }

                        let key = (entry.ip.clone(), entry.path.clone());
                        let count = request_counts.entry(key.clone()).or_insert(0);
                        *count += 1;

                        if *count >= max_duplicate_count {
                            let expiry = now + banned_duration;

                            match guard.ban_ip(&entry.ip, expiry) {
                                Ok(_) => println!(
                                    "[ReqGuard] {} banned for {} minutes",
                                    entry.ip, banned_duration_minutes
                                ),
                                Err(e) => {
                                    eprintln!("[ReqGuard] Failed to ban IP {}", entry.ip);
                                    eprintln!("{}", e);
                                }
                            }

                            request_counts.remove(&key);
                        }
                    } else {
                        eprintln!("[ReqGuard] Failed to parse log line: {}", line);
                    }

                    buffer = Vec::with_capacity(1024);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[ReqGuard] Watcher channel disconnected");
                break;
            }
        }
    }
}

fn clean_request_counts(
    log_buf: &VecDeque<LogEntry>,
    request_counts: &mut HashMap<(String, String), usize>,
) {
    let current_pairs: HashSet<(String, String)> = log_buf
        .iter()
        .map(|entry| (entry.ip.clone(), entry.path.clone()))
        .collect();

    request_counts.retain(|key, _| current_pairs.contains(key));
}
