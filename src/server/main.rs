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

use anyhow::{Context, Result};
use clap::Parser;
use slog::{info, warn};
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;
use std::path::PathBuf;
use tokio::net::UdpSocket;

use hmac_knock_lib::server::handler;
use hmac_knock_lib::server::ServerConfig;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// TOML config file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Turn debugging information on
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let raw_config = std::fs::read_to_string(&cli.config).context("Could not open config file")?;
    let config: ServerConfig =
        toml::from_str(&raw_config).context("Could not parse config contents")?;

    let mut builder = TerminalLoggerBuilder::new();
    builder.level(Severity::Info);
    builder.destination(Destination::Stderr);
    let logger = builder.build().unwrap();

    if config.hmac_secret.len() < 16 {
        warn!(logger, "VERY WEAK SECRET! Consider at least 16 characters.");
    }

    info!(logger, "Starting server...");
    info!(logger, "Listening to UDP on {}...", &config.bind);

    let sock = UdpSocket::bind(&config.bind).await?;
    let mut buf = [0; 40];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        // We only care for 40-byte messages
        // Ignore the rest for performance reasons
        if len == 40 {
            let logger_clone = logger.clone();
            let config_clone = config.clone();

            // Launch a new async task
            tokio::spawn(async move {
                handler(buf, addr, logger_clone, config_clone).await;
            });
        }
    }
}
