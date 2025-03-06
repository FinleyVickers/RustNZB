use anyhow::{Result, Context};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader, BufWriter};
use tokio_rustls::client::TlsStream;
use rustls::{ClientConfig, RootCertStore};
use tracing::debug;
use thiserror::Error;
use tokio_rustls::rustls::ServerName;

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
    #[error("Article not found (430)")]
    ArticleNotFound,
    #[error("No permission (480)")]
    NoPermission,
    #[error("Authentication required (480)")]
    AuthenticationRequired,
    #[error("Authentication failed (481/482)")]
    AuthenticationFailed,
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Connection error: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(#[from] tokio_rustls::rustls::Error),
    #[error("DNS error: {0}")]
    DnsError(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl NntpClient {
    pub fn new(config: NntpConfig) -> Self {
        Self {
            config,
            stream: None,
        }
    }

    async fn handle_response(&mut self, response: &str) -> Result<(), NntpError> {
        let code = response.split_whitespace().next()
            .ok_or_else(|| NntpError::InvalidResponse("Empty response".to_string()))?;
        
        match code {
            "430" => Err(NntpError::ArticleNotFound),
            "480" => {
                if response.to_lowercase().contains("authentication") {
                    Err(NntpError::AuthenticationRequired)
                } else {
                    Err(NntpError::NoPermission)
                }
            }
            "481" | "482" => Err(NntpError::AuthenticationFailed),
            "200" | "201" | "211" | "220" | "221" | "222" | "223" | "224" => Ok(()),
            _ => Err(NntpError::InvalidResponse(response.to_string())),
        }
    }

    pub async fn connect(&mut self) -> Result<(), NntpError> {
        let stream = if self.config.use_ssl {
            let mut root_store = RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            let tcp_stream = TcpStream::connect((self.config.host.as_str(), self.config.port))
                .await
                .map_err(NntpError::ConnectionError)?;
            
            let dns_name = ServerName::try_from(self.config.host.as_str())
                .map_err(|e| NntpError::DnsError(e.to_string()))?;
            
            let tls_stream = connector.connect(dns_name, tcp_stream)
                .await
                .map_err(|e| NntpError::TlsError(e))?;
            
            let buffered = BufReader::new(BufWriter::new(tls_stream));
            NntpStream::Tls(buffered)
        } else {
            let tcp_stream = TcpStream::connect((self.config.host.as_str(), self.config.port))
                .await
                .map_err(NntpError::ConnectionError)?;
            let buffered = BufReader::new(BufWriter::new(tcp_stream));
            NntpStream::Plain(buffered)
        };

        self.stream = Some(stream);

        // Read welcome message
        let mut response = String::new();
        match self.stream.as_mut().unwrap() {
            NntpStream::Plain(s) => {
                s.read_line(&mut response).await.map_err(NntpError::ConnectionError)?;
            }
            NntpStream::Tls(s) => {
                s.read_line(&mut response).await.map_err(NntpError::ConnectionError)?;
            }
        }

        self.handle_response(&response).await?;

        // Authenticate if credentials are provided
        let username = self.config.username.clone();
        let password = self.config.password.clone();
        
        if let (Some(username), Some(password)) = (username, password) {
            let auth_response = self.send_command(&format!("AUTHINFO USER {}", username)).await?;
            self.handle_response(&auth_response).await?;
            
            let pass_response = self.send_command(&format!("AUTHINFO PASS {}", password)).await?;
            self.handle_response(&pass_response).await?;
        }

        Ok(())
    }

    async fn send_command(&mut self, command: &str) -> Result<String, NntpError> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| NntpError::Other("Not connected".to_string()))?;
        
        // Send command
        match stream {
            NntpStream::Plain(s) => {
                s.write_all(format!("{}\r\n", command).as_bytes())
                    .await
                    .map_err(NntpError::ConnectionError)?;
                s.flush().await.map_err(NntpError::ConnectionError)?;
            }
            NntpStream::Tls(s) => {
                s.write_all(format!("{}\r\n", command).as_bytes())
                    .await
                    .map_err(NntpError::ConnectionError)?;
                s.flush().await.map_err(NntpError::ConnectionError)?;
            }
        }

        // Read response
        let mut response = String::new();
        match stream {
            NntpStream::Plain(s) => {
                s.read_line(&mut response).await.map_err(NntpError::ConnectionError)?;
            }
            NntpStream::Tls(s) => {
                s.read_line(&mut response).await.map_err(NntpError::ConnectionError)?;
            }
        }

        Ok(response)
    }

    pub async fn download_segment(&mut self, message_id: &str) -> Result<Vec<u8>, NntpError> {
        debug!("Downloading segment: {}", message_id);
        
        // Request article
        let response = self.send_command(&format!("ARTICLE {}", message_id)).await?;
        self.handle_response(&response).await?;

        // Read article data
        let mut data = Vec::new();
        let mut line = String::new();
        let mut in_body = false;

        match self.stream.as_mut().unwrap() {
            NntpStream::Plain(s) => {
                while s.read_line(&mut line).await.map_err(NntpError::ConnectionError)? > 0 {
                    if line.trim() == "." {
                        break;
                    }
                    if line.trim().is_empty() {
                        in_body = true;
                        continue;
                    }
                    if in_body {
                        data.extend_from_slice(line.as_bytes());
                    }
                    line.clear();
                }
            }
            NntpStream::Tls(s) => {
                while s.read_line(&mut line).await.map_err(NntpError::ConnectionError)? > 0 {
                    if line.trim() == "." {
                        break;
                    }
                    if line.trim().is_empty() {
                        in_body = true;
                        continue;
                    }
                    if in_body {
                        data.extend_from_slice(line.as_bytes());
                    }
                    line.clear();
                }
            }
        }

        Ok(data)
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