// Copyright 2023 Marlon Dutra

// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.

// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

// You should have received a copy of the GNU General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use super::utils::time;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_derive::Deserialize;
use sha2::Sha256;
use slog::{debug, error, info, warn, Logger};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::sleep;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub hmac_secret: String,
    pub command_open: String,
    pub command_close: String,
    pub open_timeout: u8,
    pub max_time_skew: f64,
}

#[derive(Error, Debug)]
enum HandlerError {
    #[error("Token is invalid or expired from {0}")]
    TokenExpired(String),
    #[error("HMAC signature is invalid from {0}")]
    InvalidMac(String),
    #[error("Command open failed")]
    CommandOpenFailed,
    #[error("Command close failed")]
    CommandCloseFailed,
}

// Wrapper around handler_inner, to inject ServerHandlerIOTrait dependency
pub async fn handler(buffer: [u8; 40], addr: SocketAddr, logger: Logger, config: ServerConfig) {
    let svio = ServerHandlerIO;
    match handler_inner(&svio, buffer, addr, &logger, config).await {
        Ok(()) => (),
        Err(e) => error!(logger, "{}", e),
    }
}

async fn handler_inner(
    svio: &impl ServerHandlerIOTrait,
    buffer: [u8; 40],
    addr: SocketAddr,
    logger: &Logger,
    config: ServerConfig,
) -> Result<(), HandlerError> {
    // First 8 bytes: f64 message timestamp
    // Last 32 bytes: HMAC signature
    let message = &buffer[..8];
    let hmac_sig = &buffer[8..];
    let message_ts = f64::from_le_bytes(message.try_into().unwrap());

    // Check if source is IPv4 embedded in IPv6
    // E.g. 127.0.0.1 would show as ::ffff:127.0.0.1
    let mut source_ip = String::new();
    match addr {
        SocketAddr::V4(ipv4) => source_ip.push_str(&ipv4.ip().to_string()),
        SocketAddr::V6(ipv6) => {
            match ipv6.ip().to_ipv4_mapped() {
                Some(ipv4) => source_ip.push_str(&ipv4.to_string()),

                // Native IPv6 client
                None => source_ip.push_str(&ipv6.ip().to_string()),
            }
        }
    }

    // Check for time skew and abort now
    if (time() - message_ts).abs() > config.max_time_skew {
        return Err(HandlerError::TokenExpired(addr.to_string()));
    }

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(config.hmac_secret.as_bytes()).expect("Cannot initialize HMAC");
    mac.update(message);

    match mac.verify_slice(hmac_sig) {
        Ok(_) => {
            info!(logger, "Valid message from {}", &addr);

            let cmd_open = config.command_open.replace("{}", &source_ip);
            info!(logger, "Executing open command: {}", &cmd_open);
            if let Err(_) = svio.run(&logger, &cmd_open).await {
                return Err(HandlerError::CommandOpenFailed);
            }

            info!(logger, "Sleeping for {} seconds", &config.open_timeout);
            sleep(Duration::from_secs(config.open_timeout.into())).await;

            let cmd_close = config.command_close.replace("{}", &source_ip);
            info!(logger, "Executing close command: {}", &cmd_close);
            if let Err(_) = svio.run(&logger, &cmd_close).await {
                return Err(HandlerError::CommandCloseFailed);
            }

            Ok(())
        }
        Err(..) => Err(HandlerError::InvalidMac(addr.to_string())),
    }
}

// ServerHandlerIO has the code that unit tests cannot run
struct ServerHandlerIO;

#[cfg_attr(test, automock)]
#[async_trait]
trait ServerHandlerIOTrait {
    async fn run(&self, logger: &Logger, command: &str) -> Result<(), ()>;
}

#[async_trait]
impl ServerHandlerIOTrait for ServerHandlerIO {
    async fn run(&self, logger: &Logger, command: &str) -> Result<(), ()> {
        let cmd_open = Command::new("/bin/sh").arg("-c").arg(command).spawn();

        match cmd_open {
            Ok(mut child) => {
                let status = child.wait().await;
                match status {
                    Ok(s) => {
                        if !s.success() {
                            warn!(
                                logger,
                                "Command executed but exited with status {}",
                                s.code().unwrap_or(255)
                            );
                        }
                    }
                    Err(..) => {
                        debug!(logger, "Command failed to run");
                        return Err(());
                    }
                }
            }
            Err(..) => {
                debug!(logger, "Command failed to start");
                return Err(());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests; // src/lib/server/tests.rs
