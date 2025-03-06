use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader, BufWriter};
use tokio_rustls::client::TlsStream;
use rustls::{ClientConfig, RootCertStore};
use tracing::{debug, error};
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
    #[error("Password required (381)")]
    PasswordRequired,
    #[error("Username required (381)")]
    UsernameRequired,
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Connection error: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(String),
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
        debug!("Server response: {}", response);
        
        // Some servers might include a description after the response code
        let parts: Vec<&str> = response.split_whitespace().collect();
        let code = parts.first()
            .ok_or_else(|| NntpError::InvalidResponse("Empty response".to_string()))?;
        
        match *code {
            // Standard success codes
            "200" | "201" | "211" | "215" | "220" | "221" | "222" | "223" | "224" => Ok(()),
            // Authentication success
            "281" => Ok(()),
            "381" => {
                debug!("Auth response: {}", response);
                // Some servers might send 381 without explicitly mentioning "PASS"
                Err(NntpError::PasswordRequired)
            }
            "430" => Err(NntpError::ArticleNotFound),
            "480" => {
                if response.to_lowercase().contains("authentication") {
                    Err(NntpError::AuthenticationRequired)
                } else {
                    Err(NntpError::NoPermission)
                }
            }
            "481" | "482" => Err(NntpError::AuthenticationFailed),
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
                .map_err(|e| NntpError::ConnectionError(e))?;

            // Set TCP_NODELAY for better performance
            tcp_stream.set_nodelay(true)
                .map_err(NntpError::ConnectionError)?;
            
            let dns_name = ServerName::try_from(self.config.host.as_str())
                .map_err(|e| NntpError::DnsError(e.to_string()))?;
            
            // Add retry logic for TLS connection
            let mut retry_count = 0;
            let max_retries = 3;
            let mut last_error = None;

            while retry_count < max_retries {
                match connector.connect(dns_name.clone(), tcp_stream.try_clone().await
                    .map_err(NntpError::ConnectionError)?).await {
                    Ok(tls_stream) => {
                        let buffered = BufReader::new(BufWriter::new(tls_stream));
                        break NntpStream::Tls(buffered);
                    }
                    Err(e) => {
                        error!("TLS connection attempt {} failed: {}", retry_count + 1, e);
                        last_error = Some(e);
                        retry_count += 1;
                        if retry_count < max_retries {
                            // Small delay before retry
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }

            if retry_count >= max_retries {
                return Err(NntpError::TlsError(format!("Failed after {} attempts: {}", 
                    max_retries, last_error.unwrap())));
            }
        } else {
            let tcp_stream = TcpStream::connect((self.config.host.as_str(), self.config.port))
                .await
                .map_err(NntpError::ConnectionError)?;

            // Set TCP_NODELAY for better performance
            tcp_stream.set_nodelay(true)
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
        debug!("Welcome message: {}", response);

        // Some servers might require authentication regardless of welcome message
        if let (Some(username), Some(password)) = (self.config.username.clone(), self.config.password.clone()) {
            debug!("Starting authentication for user: {}", username);
            
            // Send username
            let auth_response = self.send_command(&format!("AUTHINFO USER {}", username)).await?;
            debug!("Username response: {}", auth_response);

            // Always send password after username, regardless of response
            let pass_response = self.send_command(&format!("AUTHINFO PASS {}", password)).await?;
            debug!("Password response: {}", pass_response);

            // Check final authentication status
            match self.handle_response(&pass_response).await {
                Ok(_) => {
                    debug!("Authentication successful");
                    Ok(())
                }
                Err(NntpError::AuthenticationFailed) => {
                    error!("Authentication failed with correct credentials");
                    Err(NntpError::AuthenticationFailed)
                }
                Err(e) => {
                    error!("Unexpected error during authentication: {:?}", e);
                    Err(e)
                }
            }
        } else {
            debug!("No credentials provided, skipping authentication");
            self.handle_response(&response).await
        }
    }

    async fn send_command(&mut self, command: &str) -> Result<String, NntpError> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| NntpError::Other("Not connected".to_string()))?;
        
        debug!("Sending command: {}", command);
        
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
        debug!("Received response: {}", response);

        Ok(response)
    }

    pub async fn download_segment(&mut self, message_id: &str) -> Result<Vec<u8>, NntpError> {
        debug!("Downloading segment: {}", message_id);
        
        // Validate message ID
        if message_id.trim().is_empty() {
            error!("Empty message ID provided");
            return Err(NntpError::Other("Empty message ID provided".to_string()));
        }
        
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