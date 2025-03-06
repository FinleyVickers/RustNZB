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
use tracing::{info, error, warn};
use postprocess::PostProcessor;

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

            let nzb = nzb::NzbFile::from_file(&nzb_file)
                .context("Failed to parse NZB file")?;

            let base_output_dir = output_dir.unwrap_or_else(|| config.download_dir.clone());
            let temp_dir = config.temp_dir.join("current_download");
            std::fs::create_dir_all(&temp_dir)?;

            let multi_progress = MultiProgress::new();
            let style = ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                .unwrap();

            let connection_semaphore = Semaphore::new(config.max_connections as usize);
            let mut downloaded_files = Vec::new();

            for file in nzb.files {
                let pb = multi_progress.add(ProgressBar::new(file.segments.len() as u64));
                pb.set_style(style.clone());
                pb.set_message(file.filename.clone());

                let mut segment_data = Vec::new();
                for segment in file.segments {
                    let _permit = connection_semaphore.acquire().await?;
                    
                    // Try each server in priority order
                    let mut segment_downloaded = false;
                    for server in &config.servers {
                        let mut client = nntp::NntpClient::new(nntp::NntpConfig {
                            host: server.host.clone(),
                            port: server.port,
                            username: server.username.clone(),
                            password: server.password.clone(),
                            use_ssl: server.ssl,
                            connections: server.connections,
                        });

                        match client.connect().await {
                            Ok(_) => {
                                match client.download_segment(&segment.message_id).await {
                                    Ok(data) => {
                                        segment_data.extend(data);
                                        pb.inc(1);
                                        segment_downloaded = true;
                                        break;
                                    }
                                    Err(e) => {
                                        if !config.download.use_backup_servers {
                                            error!("Failed to download segment from {}: {}", server.name, e);
                                            break;
                                        }
                                        warn!("Failed to download segment from {}, trying next server: {}", server.name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to connect to {}: {}", server.name, e);
                                continue;
                            }
                        }
                    }

                    if !segment_downloaded {
                        error!("Failed to download segment {} from all servers", segment.message_id);
                        pb.abandon_with_message("Failed");
                        break;
                    }
                }

                if !segment_data.is_empty() {
                    let output_path = temp_dir.join(&file.filename);
                    tokio::fs::write(&output_path, segment_data).await?;
                    downloaded_files.push(output_path);
                    pb.finish_with_message("Done");
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
                
                // Clean up temp directory
                if temp_dir.exists() {
                    std::fs::remove_dir_all(temp_dir)?;
                }
                
                info!("Post-processing complete. Files extracted to: {}", base_output_dir.display());
            } else {
                // If no unpacking, just move files to the output directory
                for file in downloaded_files {
                    let target = base_output_dir.join(file.file_name().unwrap());
                    std::fs::rename(file, target)?;
                }
                info!("Download complete. Files saved to: {}", base_output_dir.display());
            }
        }
    }

    Ok(())
}
