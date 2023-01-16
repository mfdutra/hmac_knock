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
use slog::{error, info, warn, Logger};
use std::net::SocketAddr;
use std::time::Duration;
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

// Wrapper around handler_inner, to inject ServerHandlerIOTrait dependency
pub async fn handler(buffer: [u8; 40], addr: SocketAddr, logger: Logger, config: ServerConfig) {
    let svio = ServerHandlerIO;
    handler_inner(&svio, buffer, addr, logger, config).await
}

async fn handler_inner(
    svio: &impl ServerHandlerIOTrait,
    buffer: [u8; 40],
    addr: SocketAddr,
    logger: Logger,
    config: ServerConfig,
) {
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
        warn!(
            logger,
            "Invalid or expired message from {}: {}", &addr, &message_ts
        );
        return;
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
            svio.run(&logger, &cmd_open).await;

            info!(logger, "Sleeping for {} seconds", &config.open_timeout);
            sleep(Duration::from_secs(config.open_timeout.into())).await;

            let cmd_close = config.command_close.replace("{}", &source_ip);
            info!(logger, "Executing close command: {}", &cmd_close);
            svio.run(&logger, &cmd_close).await;
        }
        Err(..) => warn!(logger, "Invalid HMAC signature"),
    }
}

// ServerHandlerIO has the code that unit tests cannot run
struct ServerHandlerIO;

#[cfg_attr(test, automock)]
#[async_trait]
trait ServerHandlerIOTrait {
    async fn run(&self, logger: &Logger, command: &str);
}

#[async_trait]
impl ServerHandlerIOTrait for ServerHandlerIO {
    async fn run(&self, logger: &Logger, command: &str) {
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
                        error!(logger, "Command failed to run");
                    }
                }
            }
            Err(..) => {
                error!(logger, "Command failed to start");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sloggers::terminal::{Destination, TerminalLoggerBuilder};
    use sloggers::types::Severity;
    use sloggers::Build;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test1() {
        let mut mock = MockServerHandlerIOTrait::new();
        mock.expect_run().never();

        let buffer = [0; 40];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut builder = TerminalLoggerBuilder::new();
        builder.level(Severity::Info);
        builder.destination(Destination::Stderr);
        let logger = builder.build().unwrap();

        let config = ServerConfig {
            bind: String::from(""),
            hmac_secret: String::from("test_secret_test_test"),
            command_open: String::from(""),
            command_close: String::from(""),
            open_timeout: 0,
            max_time_skew: 2.0,
        };

        handler_inner(&mock, buffer, addr, logger, config).await;
    }
}
