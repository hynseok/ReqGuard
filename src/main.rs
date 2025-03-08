use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
    sync::Arc,
    time::Duration as StdDuration,
};

use chrono::Utc;
use notify::{RecursiveMode, Watcher};
use req_guard::{config::CONFIG, guard::IptablesGuard, models::LogEntry, parser::parse_log_line};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    sync::{mpsc, Mutex},
    time,
};

#[tokio::main]
async fn main() {
    // Load configuration
    let (max_buffer_size, max_duplicate_count, banned_duration_minutes, log_path) = {
        let config = CONFIG.lock().unwrap();
        (
            config.max_buffer_size,
            config.max_duplicate_count,
            config.banned_duration_minutes,
            config.log_path.clone(),
        )
    };

    let log_buf: Mutex<VecDeque<LogEntry>> = Mutex::new(VecDeque::with_capacity(max_buffer_size));
    let request_counts: Mutex<HashMap<(String, String), usize>> = Mutex::new(HashMap::new());
    let last_position = Mutex::new({
        match std::fs::metadata(&log_path) {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        }
    });
    let banned_duration = chrono::Duration::minutes(banned_duration_minutes);
    let mut last_cleanup = time::Instant::now();
    let cleanup_interval = StdDuration::from_secs(60);

    // Initialize the iptables guard
    let guard = Arc::new(match IptablesGuard::new("REQGUARD") {
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
    });

    // Channel to receive file events
    let (notify_tx, mut notify_rx) = mpsc::channel(100);

    // Thread for the file system watcher
    {
        let log_path = log_path.clone();
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher =
                notify::recommended_watcher(tx).expect("[ReqGuard] Failed to create watcher");
            watcher
                .watch(Path::new(&log_path), RecursiveMode::NonRecursive)
                .expect("[ReqGuard] Failed to watch log file");

            while let Ok(event) = rx.recv() {
                if notify_tx.blocking_send(event).is_err() {
                    break;
                }
            }
        });
    }

    loop {
        tokio::select! {
            // SIGINT handler
            _ = tokio::signal::ctrl_c() => {
                println!("[ReqGuard] Shutting down");
                break;
            }
            // File event handler
            event = notify_rx.recv() => {
                if event.is_none() {
                    eprintln!("[ReqGuard] Watcher channel disconnected");
                    break;
                }

                process_log(
                    &log_path,
                    &guard,
                    &log_buf,
                    &request_counts,
                    &last_position,
                    max_buffer_size,
                    max_duplicate_count,
                    banned_duration,
                    banned_duration_minutes,
                    &mut last_cleanup,
                    cleanup_interval,
                ).await;
            }
            // No events then sleep
            _ = time::sleep(StdDuration::from_secs(1)) => {
            }
        }
    }
}

// Asynchronous function to process log file changes
async fn process_log(
    log_path: &str,
    guard: &Arc<IptablesGuard>,
    log_buf: &Mutex<VecDeque<LogEntry>>,
    request_counts: &Mutex<HashMap<(String, String), usize>>,
    last_position: &Mutex<u64>,
    max_buffer_size: usize,
    max_duplicate_count: usize,
    banned_duration: chrono::Duration,
    banned_duration_minutes: i64,
    last_cleanup: &mut time::Instant,
    cleanup_interval: StdDuration,
) {
    let mut file = match File::open(log_path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ReqGuard] Failed to open log file: {}", e);
            return;
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[ReqGuard] Failed to get file metadata: {}", e);
            return;
        }
    };
    let file_size = metadata.len();

    let mut pos = last_position.lock().await;

    if file_size < *pos {
        println!("[ReqGuard] File was truncated or rotated, reading from beginning");
        *pos = 0;
    }
    if file_size == *pos {
        return;
    }

    if let Err(e) = file.seek(std::io::SeekFrom::Start(*pos)).await {
        eprintln!("[ReqGuard] Failed to seek to position {}: {}", *pos, e);
        return;
    }

    let mut reader = BufReader::with_capacity(16 * 1024, file);
    let mut line = String::new();

    while let Ok(bytes_read) = reader.read_line(&mut line).await {
        if bytes_read == 0 {
            break;
        }
        *pos += bytes_read as u64;

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let now = Utc::now();

        if last_cleanup.elapsed() >= cleanup_interval {
            let guard_clone = Arc::clone(guard);
            tokio::task::spawn_blocking(move || match guard_clone.cleanup_expired_bans() {
                Ok(expired_ips) => {
                    for ip in expired_ips {
                        println!("[ReqGuard] {} is no longer banned", ip);
                    }
                }
                Err(e) => eprintln!("[ReqGuard] Failed to cleanup expired bans: {}", e),
            })
            .await
            .ok();
            *last_cleanup = time::Instant::now();
        }

        if let Some(entry) = parse_log_line(trimmed) {
            if guard.is_banned(&entry.ip) {
                println!("[ReqGuard] {} is banned", entry.ip);
                line.clear();
                continue;
            }

            {
                let mut buf = log_buf.lock().await;
                buf.push_back(entry.clone());
                if buf.len() > max_buffer_size {
                    buf.pop_front();
                    let mut counts = request_counts.lock().await;
                    clean_request_counts(&buf, &mut counts);
                }
            }

            let key = (entry.ip.clone(), entry.path.clone());
            let mut counts = request_counts.lock().await;
            let count = counts.entry(key.clone()).or_insert(0);
            *count += 1;

            if *count >= max_duplicate_count {
                let expiry = now + banned_duration;
                let ip_clone = entry.ip.clone();
                let guard_clone = Arc::clone(guard);
                tokio::task::spawn_blocking(move || match guard_clone.ban_ip(&ip_clone, expiry) {
                    Ok(_) => println!(
                        "[ReqGuard] {} banned for {} minutes",
                        ip_clone, banned_duration_minutes
                    ),
                    Err(e) => {
                        eprintln!("[ReqGuard] Failed to ban IP {}", ip_clone);
                        eprintln!("{}", e);
                    }
                })
                .await
                .ok();
                counts.remove(&key);
            }
        } else {
            eprintln!("[ReqGuard] Failed to parse log line: {}", trimmed);
        }

        line.clear();
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
