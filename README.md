# ReqGuard
ReqGuard is a Rust-based tool designed to monitor web server log files and automatically ban IP addresses that exceed a request threshold using iptables.

## Prerequisites
* **Linux Environment**:
Since iptables is Linux-specific, ReqGuard is designed to run on Linux-based systems.

* **Rust Toolchain**:
ReqGuard is built with Rust. Ensure you have the latest stable Rust toolchain installed.

## Installation
#### 1. Clone the Repository
```bash
git clone https://github.com/hynseok/ReqGuard.git
cd ReqGuard
```

#### 2. Build the Program
Use cargo to build the program:
```bash
cargo build --release
```
#### 3. Configuration
Edit the configuration file `config.toml`

* **max_buffer_size**: Maximum number of log entries that can be stored in window.
* **max_duplicate_count**: Threshold for duplicate requests before banning an IP.
* **banned_duration_minutes**: How long (in minutes) an IP remains banned.
* **log_path**: Path to the log file to monitor.
* **log_regex**: Regular expression used to extract valid log entries.
* **dports**: Specifies the target destination port(s).
* **kube_proxy**: Flag that indicates whether the application is running in a Kubernetes. When set to true, the `KUBE-PROXY-FIREWALL` chain is changed.

## Usage
After building, run the binary:
```bash
sudo ./target/release/req_guard
```

## Troubleshooting
#### 1. Watcher issues:
Log watcher uses file system notifier(inotify), it might be exceeding inotify limits. Increase them using:
```bash
sysctl -w fs.inotify.max_user_watches=524288
sysctl -w fs.inotify.max_user_instances=524288
sysctl -w fs.inotify.max_queued_events=524288
```