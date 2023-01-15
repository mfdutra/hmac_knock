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
use hmac::{Hmac, Mac};
use hmac_knock_lib::utils::time;
use serde_derive::Deserialize;
use sha2::Sha256;
use std::net::UdpSocket;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Destination hostname
    hostname: String,

    /// Port number
    port: u16,

    /// TOML config file
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "/etc/hmac_knock_client.toml"
    )]
    config: PathBuf,

    /// Send over IPv6 instead of IPv4
    #[arg(long, short = '6')]
    ipv6: bool,
}

#[derive(Deserialize, Debug)]
struct ClientConfig {
    hmac_secret: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let raw_config = std::fs::read_to_string(&cli.config).context("Could not open config file")?;
    let config: ClientConfig =
        toml::from_str(&raw_config).context("Could not parse config contents")?;

    // Current f64 time to little-endian 8 bytes
    let now_bytes: [u8; 8] = time().to_le_bytes();

    // HMAC that with secret from config file
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&config.hmac_secret.as_bytes())?;
    mac.update(&now_bytes);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    // Create a single 40-byte message to send
    // First 8 bytes: f64 message timestamp
    // Last 32 bytes: HMAC signature
    let mut message = [0; 40];
    now_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i] = *b;
    });
    hmac_bytes.iter().enumerate().for_each(|(i, b)| {
        message[i + 8] = *b;
    });

    let bind_addr = if cli.ipv6 { ":::0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind_addr)?;
    socket
        .send_to(&message, format!("{}:{}", &cli.hostname, &cli.port))
        .context("Failed to send UDP message")?;

    Ok(())
}
