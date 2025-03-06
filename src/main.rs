mod config;
mod nntp;
mod nzb;
mod postprocess;

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use config::{Config, ServerConfig};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tokio::sync::Semaphore;
use tracing::{info, error, warn, debug};
use postprocess::PostProcessor;
use directories;
use futures::stream::{StreamExt, FuturesUnordered};
use std::sync::Arc;
use crate::nzb::Segment;
use std::io::BufRead;

struct YencDecoder {
    line_length: usize,
    part_size: usize,
    part_begin: usize,
    part_end: usize,
}

impl YencDecoder {
    fn new() -> Self {
        Self {
            line_length: 128,
            part_size: 0,
            part_begin: 0,
            part_end: 0,
        }
    }

    fn begin(&mut self, line: &[u8]) -> Result<()> {
        // Parse =ybegin line
        let line_str = String::from_utf8_lossy(line);
        if let Some(size) = line_str.split_whitespace()
            .find(|s| s.starts_with("size="))
            .and_then(|s| s.split('=').nth(1))
            .and_then(|s| s.parse::<usize>().ok()) {
            self.part_size = size;
        }
        if let Some(line) = line_str.split_whitespace()
            .find(|s| s.starts_with("line="))
            .and_then(|s| s.split('=').nth(1))
            .and_then(|s| s.parse::<usize>().ok()) {
            self.line_length = line;
        }
        Ok(())
    }

    fn part(&mut self, line: &[u8]) -> Result<()> {
        // Parse =ypart line
        let line_str = String::from_utf8_lossy(line);
        if let (Some(begin), Some(end)) = (
            line_str.split_whitespace()
                .find(|s| s.starts_with("begin="))
                .and_then(|s| s.split('=').nth(1))
                .and_then(|s| s.parse::<usize>().ok()),
            line_str.split_whitespace()
                .find(|s| s.starts_with("end="))
                .and_then(|s| s.split('=').nth(1))
                .and_then(|s| s.parse::<usize>().ok())
        ) {
            self.part_begin = begin;
            self.part_end = end;
        }
        Ok(())
    }

    fn decode(&self, line: &[u8], output: &mut Vec<u8>) -> Result<()> {
        let mut i = 0;
        while i < line.len() {
            let byte = line[i];
            
            // Skip any CR/LF
            if byte == b'\r' || byte == b'\n' {
                i += 1;
                continue;
            }
            
            // Handle escape sequences
            if byte == b'=' {
                if i + 1 < line.len() {
                    // Get the next byte and decode it
                    i += 1;
                    let escaped_byte = line[i];
                    let decoded = ((escaped_byte as i16 - 64) & 0xFF) as u8;
                    output.push(decoded);
                }
            } else {
                // Normal yEnc decoding
                let decoded = ((byte as i16 - 42) & 0xFF) as u8;
                output.push(decoded);
            }
            i += 1;
        }
        Ok(())
    }

    fn end(&self, line: &[u8]) -> Result<()> {
        // Parse =yend line for size verification
        let line_str = String::from_utf8_lossy(line);
        if let Some(size) = line_str.split_whitespace()
            .find(|s| s.starts_with("size="))
            .and_then(|s| s.split('=').nth(1))
            .and_then(|s| s.parse::<usize>().ok()) {
            if size != self.part_size && self.part_size != 0 {
                warn!("yEnc size mismatch: expected {}, got {}", self.part_size, size);
            }
        }
        Ok(())
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new Usenet server
    AddServer {
        #[arg(long)]
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "119")]
        port: u16,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        ssl: bool,
        #[arg(long, default_value = "0")]
        priority: u32,
        #[arg(long)]
        retention_days: Option<u32>,
    },
    /// Remove a server by name
    RemoveServer {
        #[arg(long)]
        name: String,
    },
    /// List configured servers
    ListServers,
    /// Configure download settings
    ConfigureDownload {
        #[arg(long)]
        download_dir: Option<PathBuf>,
        #[arg(long)]
        max_connections: Option<u32>,
        #[arg(long)]
        verify_checksums: Option<bool>,
        #[arg(long)]
        retry_attempts: Option<u32>,
        #[arg(long)]
        speed_limit: Option<u64>,
    },
    /// Configure post-processing settings
    ConfigurePostProcess {
        #[arg(long)]
        auto_extract: Option<bool>,
        #[arg(long)]
        cleanup_archives: Option<bool>,
        #[arg(long)]
        create_folders: Option<bool>,
        #[arg(long)]
        folder_pattern: Option<String>,
        #[arg(long)]
        process_par2: Option<bool>,
    },
    /// Show current configuration
    ShowConfig,
    /// Download an NZB file
    Download {
        #[arg(name = "NZB_FILE")]
        nzb_file: PathBuf,
        #[arg(long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        no_unpack: bool,
    },
}

async fn download_segment(
    segment: &Segment,
    servers: &[ServerConfig],
    connection_semaphore: Arc<Semaphore>,
    config: &Config,
) -> Result<(u32, Vec<u8>)> {
    let _permit = connection_semaphore.acquire().await?;
    
    // Try each server in priority order
    for server in servers {
        debug!("Trying server: {} for segment {}", server.name, segment.number);
        let mut client = nntp::NntpClient::new(nntp::NntpConfig {
            host: server.host.clone(),
            port: server.port,
            username: server.username.clone(),
            password: server.password.clone(),
            use_ssl: server.ssl,
            connections: server.connections,
        });

        match client.try_connect().await {
            Ok(_) => {
                debug!("Connected to server {}", server.name);
                match client.download_segment(&segment.message_id).await {
                    Ok(raw_data) => {
                        debug!("Successfully downloaded segment {} ({} bytes)", segment.number, raw_data.len());
                        
                        // Process yEnc encoded data
                        let mut decoder = YencDecoder::new();
                        let mut decoded_data = Vec::with_capacity(segment.bytes as usize);
                        
                        // Find yEnc header
                        let mut found_header = false;
                        let mut in_data = false;
                        
                        for line in raw_data.split(|&b| b == b'\n') {
                            // Trim any trailing CR
                            let line = if line.ends_with(&[b'\r']) {
                                &line[..line.len()-1]
                            } else {
                                line
                            };
                            
                            if line.starts_with(b"=ybegin ") {
                                found_header = true;
                                decoder.begin(line)?;
                            } else if found_header && line.starts_with(b"=ypart ") {
                                decoder.part(line)?;
                                in_data = true;
                            } else if line.starts_with(b"=yend") {
                                decoder.end(line)?;
                                break;
                            } else if in_data && !line.is_empty() {
                                decoder.decode(line, &mut decoded_data)?;
                            }
                        }
                        
                        if !found_header {
                            // If no yEnc header found, assume raw binary data
                            debug!("No yEnc encoding found, using raw data for segment {}", segment.number);
                            return Ok((segment.number, raw_data));
                        }
                        
                        debug!("Successfully decoded yEnc segment {} ({} bytes)", segment.number, decoded_data.len());
                        return Ok((segment.number, decoded_data));
                    }
                    Err(e) => {
                        if !config.download.use_backup_servers {
                            error!("Failed to download segment {} from {}: {}", segment.number, server.name, e);
                            break;
                        }
                        warn!("Failed to download segment {} from {}, trying next server: {}", segment.number, server.name, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to connect to {}: {}", server.name, e);
                continue;
            }
        }
    }
    
    Err(anyhow::anyhow!("Failed to download segment {} from all servers", segment.message_id))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let mut config = Config::load()?;

    match cli.command {
        Commands::AddServer {
            name,
            host,
            port,
            username,
            password,
            ssl,
            priority,
            retention_days,
        } => {
            let server = ServerConfig {
                name: name.clone(),
                host,
                port,
                username,
                password,
                connections: 4,
                ssl,
                priority,
                retention_days,
                timeout: None,
            };

            // Remove any existing server with the same name
            config.servers.retain(|s| s.name != name);
            config.servers.push(server);
            // Sort servers by priority
            config.servers.sort_by_key(|s| s.priority);
            
            config.save()?;
            info!("Server '{}' added successfully", name);
        }
        Commands::RemoveServer { name } => {
            let initial_len = config.servers.len();
            config.servers.retain(|s| s.name != name);
            
            if config.servers.len() < initial_len {
                config.save()?;
                info!("Server '{}' removed successfully", name);
            } else {
                error!("No server found with name '{}'", name);
            }
        }
        Commands::ListServers => {
            if config.servers.is_empty() {
                println!("No servers configured");
                return Ok(());
            }

            println!("Configured servers (in priority order):");
            for server in &config.servers {
                println!("\nServer: {}", server.name);
                println!("  Host: {}:{}", server.host, server.port);
                println!("  SSL: {}", server.ssl);
                println!("  Priority: {}", server.priority);
                println!("  Connections: {}", server.connections);
                if let Some(days) = server.retention_days {
                    println!("  Retention: {} days", days);
                }
                println!("  Authentication: {}", server.username.is_some());
            }
        }
        Commands::ConfigureDownload {
            download_dir,
            max_connections,
            verify_checksums,
            retry_attempts,
            speed_limit,
        } => {
            if let Some(dir) = download_dir {
                config.download_dir = dir;
            }
            if let Some(conn) = max_connections {
                config.max_connections = conn;
            }
            if let Some(verify) = verify_checksums {
                config.download.verify_checksums = verify;
            }
            if let Some(retry) = retry_attempts {
                config.download.retry_attempts = retry;
            }
            if let Some(limit) = speed_limit {
                config.download.speed_limit = limit;
            }

            config.save()?;
            info!("Download settings updated successfully");
        }
        Commands::ConfigurePostProcess {
            auto_extract,
            cleanup_archives,
            create_folders,
            folder_pattern,
            process_par2,
        } => {
            if let Some(extract) = auto_extract {
                config.post_processing.auto_extract = extract;
            }
            if let Some(cleanup) = cleanup_archives {
                config.post_processing.cleanup_archives = cleanup;
            }
            if let Some(folders) = create_folders {
                config.post_processing.create_folders = folders;
            }
            if let Some(pattern) = folder_pattern {
                config.post_processing.folder_naming_pattern = pattern;
            }
            if let Some(par2) = process_par2 {
                config.post_processing.process_par2 = par2;
            }

            config.save()?;
            info!("Post-processing settings updated successfully");
        }
        Commands::ShowConfig => {
            let config_yaml = serde_yaml::to_string(&config)?;
            println!("Current configuration:\n{}", config_yaml);
        }
        Commands::Download { nzb_file, output_dir, no_unpack } => {
            if config.servers.is_empty() {
                error!("No servers configured. Please add a server first using the add-server command.");
                return Ok(());
            }

            info!("Starting download of NZB file: {}", nzb_file.display());
            let nzb = nzb::NzbFile::from_file(&nzb_file)
                .context("Failed to parse NZB file")?;

            info!("Found {} files in NZB", nzb.files.len());
            for file in &nzb.files {
                info!("File: {} ({} segments, {} bytes)", file.filename, file.segments.len(), file.bytes);
            }

            let base_output_dir = output_dir.unwrap_or_else(|| config.download_dir.clone());
            info!("Output directory: {}", base_output_dir.display());
            
            // Create temp directory in user's cache directory
            let cache_dir = directories::ProjectDirs::from("com", "rustnzb", "rustnzb")
                .context("Failed to determine cache directory")?
                .cache_dir()
                .to_path_buf();
            let temp_dir = cache_dir.join("current_download");
            info!("Temporary directory: {}", temp_dir.display());
            
            // Ensure temp directory exists and is clean
            if temp_dir.exists() {
                info!("Cleaning temporary directory");
                std::fs::remove_dir_all(&temp_dir)?;
            }
            std::fs::create_dir_all(&temp_dir)?;

            // Ensure output directory exists
            std::fs::create_dir_all(&base_output_dir)?;

            let multi_progress = MultiProgress::new();
            let style = ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                .unwrap();

            let connection_semaphore = Arc::new(Semaphore::new(config.max_connections as usize));
            let mut downloaded_files = Vec::new();

            for file in nzb.files {
                let total_segments = file.segments.len();
                info!("Processing file: {} ({} segments)", file.filename, total_segments);
                
                let pb = multi_progress.add(ProgressBar::new(total_segments as u64));
                pb.set_style(style.clone());
                pb.set_message(format!("[{} bytes] {}", file.bytes, file.filename));

                let mut segment_data = vec![Vec::new(); total_segments];
                let mut download_failed = false;

                // Create a FuturesUnordered to handle parallel downloads
                let mut downloads = FuturesUnordered::new();
                
                // Start all segment downloads in parallel
                for segment in &file.segments {
                    let semaphore = Arc::clone(&connection_semaphore);
                    let segment = segment.clone();
                    let servers = config.servers.clone();
                    let config = config.clone();
                    
                    downloads.push(tokio::spawn(async move {
                        download_segment(&segment, &servers, semaphore, &config).await
                    }));
                }

                // Process completed downloads as they finish
                while let Some(result) = downloads.next().await {
                    match result {
                        Ok(Ok((number, data))) => {
                            let index = (number - 1) as usize;
                            segment_data[index] = data;
                            pb.inc(1);
                            pb.set_message(format!("[{}/{} segments]", pb.position(), total_segments));
                        }
                        Ok(Err(e)) => {
                            error!("Segment download failed: {}", e);
                            download_failed = true;
                            break;
                        }
                        Err(e) => {
                            error!("Task failed: {}", e);
                            download_failed = true;
                            break;
                        }
                    }
                }

                if !download_failed {
                    // Verify all segments are present and non-empty
                    if segment_data.iter().any(|data| data.is_empty()) {
                        error!("Some segments are missing or empty");
                        pb.abandon_with_message("Failed: Missing segments");
                        continue;
                    }

                    // Combine all segments in order
                    let mut combined_data = Vec::with_capacity(file.bytes as usize);
                    for (i, segment) in segment_data.into_iter().enumerate() {
                        debug!("Adding segment {} ({} bytes) to combined data", i + 1, segment.len());
                        combined_data.extend(segment);
                    }

                    if !combined_data.is_empty() {
                        let safe_filename = if file.filename.is_empty() {
                            sanitize_filename::sanitize(&file.subject)
                        } else {
                            sanitize_filename::sanitize(&file.filename)
                        };
                        
                        if safe_filename.is_empty() {
                            error!("Invalid filename for segment: {}", file.subject);
                            pb.abandon_with_message("Failed: Invalid filename");
                            continue;
                        }
                        
                        let output_path = temp_dir.join(&safe_filename);
                        debug!("Writing file to: {}", output_path.display());
                        
                        if output_path.exists() {
                            if output_path.is_dir() {
                                std::fs::remove_dir_all(&output_path)?;
                            } else {
                                std::fs::remove_file(&output_path)?;
                            }
                        }
                        
                        if let Some(parent) = output_path.parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }
                        
                        info!("Writing file: {} ({} bytes)", output_path.display(), combined_data.len());
                        tokio::fs::write(&output_path, &combined_data).await?;
                        
                        // Verify file size matches expected size
                        let written_size = output_path.metadata()?.len();
                        if written_size != file.bytes {
                            warn!("File size mismatch: expected {} bytes, got {} bytes", file.bytes, written_size);
                        }
                        
                        downloaded_files.push(output_path);
                        pb.finish_with_message(format!("Done: {} ({} bytes)", safe_filename, combined_data.len()));
                    }
                } else {
                    pb.abandon_with_message("Failed: Some segments could not be downloaded");
                }
            }

            if !no_unpack && config.post_processing.auto_extract {
                info!("Post-processing downloaded files...");
                let post_processor = PostProcessor::new(
                    temp_dir.clone(),
                    base_output_dir.clone(),
                );

                let job_name = nzb.meta.title.unwrap_or_else(|| {
                    nzb_file
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string()
                });

                post_processor.process_download(&job_name, downloaded_files).await?;
                
                if temp_dir.exists() {
                    info!("Cleaning up temporary directory");
                    std::fs::remove_dir_all(temp_dir)?;
                }
                
                info!("Post-processing complete. Files extracted to: {}", base_output_dir.display());
            } else {
                // If no unpacking, just move files to the output directory
                info!("Moving files to output directory");
                std::fs::create_dir_all(&base_output_dir)?;
                for file in downloaded_files {
                    let target = base_output_dir.join(file.file_name().unwrap());
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    info!("Moving file: {} -> {}", file.display(), target.display());
                    std::fs::rename(file, target)?;
                }
                info!("Download complete. Files saved to: {}", base_output_dir.display());
            }
        }
    }

    Ok(())
}
