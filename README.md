# RustNZB

A fast and efficient CLI-based NZB client written in Rust. This client allows you to download from Usenet servers using NZB files.

## Features

- Fast, concurrent downloads using async Rust
- Multiple server support with priority-based failover
- SSL/TLS support
- Progress bars for download tracking
- Simple YAML configuration
- Command-line interface

## Installation

### From Source

1. Make sure you have Rust installed (https://rustup.rs/)
2. Clone this repository
3. Build the project:
```bash
cargo build --release
```
4. The binary will be available in `target/release/rustnzb`

## Usage

### Adding a Usenet Server

Before downloading, you need to configure at least one Usenet server:

```bash
rustnzb add-server --name "MyServer" --host "news.example.com" --port 119 --username "user" --password "pass" --ssl --priority 0 --retention-days 3000
```

### Downloading an NZB File

To download content from an NZB file:

```bash
rustnzb download path/to/file.nzb --output-dir /path/to/output
```

If no output directory is specified, files will be saved to the default download directory.

## Configuration

The configuration file is automatically created at first run in the following location:
- macOS: `~/Library/Application Support/com.rustnzb.rustnzb/config.yaml`
- Linux: `~/.config/rustnzb/config.yaml`
- Windows: `%APPDATA%\rustnzb\config.yaml`

An example configuration file (`config.example.yaml`) is also created to help you get started. The configuration uses YAML format and includes settings for:

```yaml
servers:
  - name: "Primary Server"
    host: "news.example.com"
    port: 563
    username: "user"
    password: "pass"
    connections: 10
    ssl: true
    priority: 0
    retention_days: 3000

download:
  verify_checksums: true
  retry_attempts: 3
  auto_repair: true
  use_backup_servers: true
  speed_limit: 0  # 0 means unlimited

post_processing:
  auto_extract: true
  cleanup_archives: true
  create_folders: true
  folder_naming_pattern: "{title} ({category})"
  process_par2: true
  skip_categories: ["software", "games"]
```

You can also configure settings via CLI commands:
```bash
# Configure download settings
rustnzb configure-download --download-dir ~/Downloads/usenet --max-connections 20

# Configure post-processing
rustnzb configure-post-process --auto-extract true --create-folders true

# View current configuration
rustnzb show-config
```

## Building from Source

1. Install Rust using rustup
2. Clone the repository
3. Run:
```bash
cargo build --release
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 