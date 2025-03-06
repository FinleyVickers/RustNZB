use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
use tracing::{debug, error};
use tokio_rustls::TlsConnector;
use std::sync::Arc;

pub struct NntpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_ssl: bool,
    pub connections: u32,
}

#[async_trait]
pub trait NntpConnection: Send + Sync {
    async fn connect(&mut self) -> Result<()>;
    async fn download_segment(&mut self, message_id: &str) -> Result<Vec<u8>>;
}

pub struct NntpClient {
    config: NntpConfig,
    stream: Option<NntpStream>,
}

enum NntpStream {
    Plain(BufReader<BufWriter<TcpStream>>),
    Tls(BufReader<BufWriter<TlsStream<TcpStream>>>),
}

#[derive(Debug, thiserror::Error)]
pub enum NntpError {
    #[error("Connection error: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("DNS error: {0}")]
    DnsError(String),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Invalid message ID")]
    InvalidMessageId,
    #[error("Article not found (430/423)")]
    ArticleNotFound,
    #[error("Other error: {0}")]
    Other(String),
}

impl NntpClient {
    pub fn new(config: NntpConfig) -> Self {
        NntpClient {
            config,
            stream: None,
        }
    }

    async fn read_response(&mut self) -> Result<String, NntpError> {
        let mut response = String::new();
        match self.stream.as_mut().unwrap() {
            NntpStream::Plain(s) => {
                s.read_line(&mut response).await?;
            }
            NntpStream::Tls(s) => {
                s.read_line(&mut response).await?;
            }
        }
        Ok(response)
    }

    async fn send_command(&mut self, command: &str) -> Result<(), NntpError> {
        debug!("Sending command: {}", command);
        let cmd = format!("{}\r\n", command);
        match self.stream.as_mut().unwrap() {
            NntpStream::Plain(s) => {
                s.write_all(cmd.as_bytes()).await?;
                s.flush().await?;
            }
            NntpStream::Tls(s) => {
                s.write_all(cmd.as_bytes()).await?;
                s.flush().await?;
            }
        }
        Ok(())
    }

    pub async fn try_connect(&mut self) -> Result<(), NntpError> {
        let host = self.config.host.clone();
        let port = self.config.port;
        let use_ssl = self.config.use_ssl;
        self.connect(&host, port, use_ssl).await
    }

    async fn create_tls_connector() -> Result<TlsConnector, NntpError> {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Allow legacy protocols and ciphers for compatibility
        config.alpn_protocols.clear();
        
        // Create connector
        let connector = TlsConnector::from(Arc::new(config));
        Ok(connector)
    }

    pub async fn connect(&mut self, host: &str, port: u16, use_tls: bool) -> Result<(), NntpError> {
        let tcp_stream = TcpStream::connect((host, port)).await?;
        tcp_stream.set_nodelay(true)?;

        if use_tls {
            let connector = Self::create_tls_connector().await?;
            let domain = ServerName::try_from(host)
                .map_err(|_| NntpError::Other("Invalid hostname".to_string()))?;

            // Try plain TLS first
            match connector.connect(domain.clone(), tcp_stream).await {
                Ok(tls_stream) => {
                    self.stream = Some(NntpStream::Tls(BufReader::new(BufWriter::new(tls_stream))));
                }
                Err(e) => {
                    debug!("TLS connection failed: {}", e);
                    // If TLS fails, try connecting without TLS
                    let tcp_stream = TcpStream::connect((host, port)).await?;
                    tcp_stream.set_nodelay(true)?;
                    self.stream = Some(NntpStream::Plain(BufReader::new(BufWriter::new(tcp_stream))));
                }
            }
        } else {
            self.stream = Some(NntpStream::Plain(BufReader::new(BufWriter::new(tcp_stream))));
        }

        // Read welcome message
        let welcome = self.read_response().await?;
        debug!("Welcome message: {}", welcome);

        // Authenticate if credentials are provided
        let username = self.config.username.as_ref().cloned();
        let password = self.config.password.as_ref().cloned();

        if let (Some(username), Some(password)) = (username, password) {
            debug!("Starting authentication for user: {}", username);
            
            // Send username
            let username_cmd = format!("AUTHINFO USER {}", username);
            debug!("Sending command: {}", username_cmd);
            self.send_command(&username_cmd).await?;
            let user_response = self.read_response().await?;
            debug!("Username response: {}", user_response);

            // Send password
            let password_cmd = format!("AUTHINFO PASS {}", password);
            debug!("Sending command: {}", password_cmd);
            self.send_command(&password_cmd).await?;
            let pass_response = self.read_response().await?;
            debug!("Password response: {}", pass_response);

            // Check final response
            debug!("Server response: {}", pass_response);
            if pass_response.starts_with("281") {
                debug!("Authentication successful");
            } else {
                return Err(NntpError::AuthenticationFailed);
            }
        }

        Ok(())
    }

    pub async fn download_segment(&mut self, message_id: &str) -> Result<Vec<u8>, NntpError> {
        if message_id.is_empty() {
            return Err(NntpError::InvalidMessageId);
        }

        // Try to get the article directly first
        debug!("Downloading segment: {}", message_id);
        self.send_command(&format!("ARTICLE <{}>", message_id)).await?;
        
        // Read the response line as UTF-8 since it's a text command response
        let response = self.read_response().await?;
        debug!("Article response: {}", response);

        if response.starts_with("220") {
            // Article found, read the data as raw bytes
            let mut data = Vec::new();
            let mut line_bytes = Vec::new();
            let mut total_bytes = 0;
            
            match self.stream.as_mut().unwrap() {
                NntpStream::Plain(s) => {
                    loop {
                        line_bytes.clear();
                        let bytes_read = s.read_until(b'\n', &mut line_bytes).await?;
                        if bytes_read == 0 {
                            break;
                        }
                        // Check for end of article marker
                        if line_bytes.len() == 3 && line_bytes[0] == b'.' && line_bytes[1] == b'\r' && line_bytes[2] == b'\n' {
                            break;
                        }
                        // Handle dot-stuffing: if line starts with .., remove one .
                        if line_bytes.starts_with(b"..") {
                            data.extend_from_slice(&line_bytes[1..]);
                            total_bytes += line_bytes.len() - 1;
                        } else {
                            data.extend_from_slice(&line_bytes);
                            total_bytes += line_bytes.len();
                        }
                        debug!("Downloaded {} bytes", total_bytes);
                    }
                }
                NntpStream::Tls(s) => {
                    loop {
                        line_bytes.clear();
                        let bytes_read = s.read_until(b'\n', &mut line_bytes).await?;
                        if bytes_read == 0 {
                            break;
                        }
                        // Check for end of article marker
                        if line_bytes.len() == 3 && line_bytes[0] == b'.' && line_bytes[1] == b'\r' && line_bytes[2] == b'\n' {
                            break;
                        }
                        // Handle dot-stuffing: if line starts with .., remove one .
                        if line_bytes.starts_with(b"..") {
                            data.extend_from_slice(&line_bytes[1..]);
                            total_bytes += line_bytes.len() - 1;
                        } else {
                            data.extend_from_slice(&line_bytes);
                            total_bytes += line_bytes.len();
                        }
                        debug!("Downloaded {} bytes", total_bytes);
                    }
                }
            }

            debug!("Segment download complete. Total bytes: {}", total_bytes);
            Ok(data)
        } else if response.starts_with("430") || response.starts_with("423") {
            // Article not found
            Err(NntpError::ArticleNotFound)
        } else {
            // Other error
            Err(NntpError::Other(format!("Unexpected response: {}", response)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nntp_client_creation() {
        let config = NntpConfig {
            host: "news.example.com".to_string(),
            port: 119,
            username: None,
            password: None,
            use_ssl: false,
            connections: 1,
        };

        let client = NntpClient::new(config);
        assert!(client.stream.is_none());
    }
} 