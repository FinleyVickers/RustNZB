use anyhow::{Result, Context};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// List of Usenet servers in priority order
    pub servers: Vec<ServerConfig>,
    /// Default directory for completed downloads
    pub download_dir: PathBuf,
    /// Directory for temporary files during download and processing
    pub temp_dir: PathBuf,
    /// Maximum concurrent connections across all servers
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Download settings
    pub download: DownloadConfig,
    /// Post-processing settings
    pub post_processing: PostProcessConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    /// Server name for identification
    pub name: String,
    /// Server hostname
    pub host: String,
    /// Server port
    pub port: u16,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
    /// Maximum connections for this server
    pub connections: u32,
    /// Whether to use SSL/TLS
    pub ssl: bool,
    /// Server priority (lower number = higher priority)
    pub priority: u32,
    /// Server retention days
    pub retention_days: Option<u32>,
    /// Optional server level connection timeout
    pub timeout: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DownloadConfig {
    /// Whether to verify article checksums
    pub verify_checksums: bool,
    /// Number of retry attempts for failed articles
    pub retry_attempts: u32,
    /// Whether to automatically repair using par2 files
    pub auto_repair: bool,
    /// Whether to automatically retry with backup servers
    pub use_backup_servers: bool,
    /// Maximum download speed in bytes per second (0 = unlimited)
    pub speed_limit: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostProcessConfig {
    /// Whether to automatically extract archives
    pub auto_extract: bool,
    /// Whether to delete archives after successful extraction
    pub cleanup_archives: bool,
    /// Whether to create folders for extracted content
    pub create_folders: bool,
    /// Pattern for naming created folders
    pub folder_naming_pattern: String,
    /// Whether to process par2 files for repair
    pub process_par2: bool,
    /// Categories to skip post-processing for
    pub skip_categories: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let proj_dirs = ProjectDirs::from("com", "rustnzb", "rustnzb")
            .expect("Failed to determine project directories");

        Self {
            servers: Vec::new(),
            download_dir: proj_dirs.data_dir().join("downloads"),
            temp_dir: proj_dirs.cache_dir().to_path_buf(),
            max_connections: 4,
            connection_timeout: 30,
            download: DownloadConfig::default(),
            post_processing: PostProcessConfig::default(),
        }
    }
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            verify_checksums: true,
            retry_attempts: 3,
            auto_repair: true,
            use_backup_servers: true,
            speed_limit: 0,
        }
    }
}

impl Default for PostProcessConfig {
    fn default() -> Self {
        Self {
            auto_extract: true,
            cleanup_archives: true,
            create_folders: true,
            folder_naming_pattern: "{title}".to_string(),
            process_par2: true,
            skip_categories: vec!["software".to_string()],
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        
        if !config_path.exists() {
            let config = Config::default();
            config.save()?;
            return Ok(config);
        }

        let config_str = fs::read_to_string(&config_path)
            .context("Failed to read config file")?;
        
        serde_yaml::from_str(&config_str)
            .context("Failed to parse config file")
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        let config_str = serde_yaml::to_string(self)
            .context("Failed to serialize config")?;
        
        fs::write(&config_path, config_str)
            .context("Failed to write config file")?;
        
        // Create example config if it doesn't exist
        let example_path = config_path.with_extension("example.yaml");
        if !example_path.exists() {
            let example_config = Self::create_example_config();
            let example_str = serde_yaml::to_string(&example_config)
                .context("Failed to serialize example config")?;
            fs::write(&example_path, example_str)
                .context("Failed to write example config file")?;
        }
        
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "rustnzb", "rustnzb")
            .context("Failed to determine project directories")?;
        
        Ok(proj_dirs.config_dir().join("config.yaml"))
    }

    fn create_example_config() -> Self {
        let proj_dirs = ProjectDirs::from("com", "rustnzb", "rustnzb")
            .expect("Failed to determine project directories");

        let mut config = Config::default();
        config.servers = vec![
            ServerConfig {
                name: "Primary Server".to_string(),
                host: "news.example.com".to_string(),
                port: 563,
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                connections: 10,
                ssl: true,
                priority: 0,
                retention_days: Some(3000),
                timeout: Some(30),
            },
            ServerConfig {
                name: "Backup Server".to_string(),
                host: "news2.example.com".to_string(),
                port: 119,
                username: None,
                password: None,
                connections: 4,
                ssl: false,
                priority: 1,
                retention_days: Some(1000),
                timeout: None,
            },
        ];

        config.download_dir = proj_dirs.data_dir().join("downloads");
        config.temp_dir = proj_dirs.cache_dir().join("temp");
        config.max_connections = 20;
        config.connection_timeout = 30;

        config.download = DownloadConfig {
            verify_checksums: true,
            retry_attempts: 3,
            auto_repair: true,
            use_backup_servers: true,
            speed_limit: 0,
        };

        config.post_processing = PostProcessConfig {
            auto_extract: true,
            cleanup_archives: true,
            create_folders: true,
            folder_naming_pattern: "{title} ({category})".to_string(),
            process_par2: true,
            skip_categories: vec!["software".to_string(), "games".to_string()],
        };

        config
    }
} 