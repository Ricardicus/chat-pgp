use clap::Parser;
#[allow(dead_code)]
mod pgp;
#[allow(dead_code)]
mod session;
mod util;
use session::crypto::{PGPEnCryptOwned, PGPEnDeCrypt};
use session::messages::{MessagingError, SessionMessage};
use session::Session;
use std::sync::Arc;

use std::fs;

#[allow(unused_imports)]
use pgp::pgp::generate_new_key;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[clap(short, long)]
    #[arg(default_value = "zenoh/config.json5")]
    zenoh_config: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let zenoh_config = cli.zenoh_config;

    let cert = Arc::new(generate_new_key().unwrap());

    let passphrase = String::new();
    let pgp_handler = PGPEnDeCrypt::new(cert.clone(), &passphrase);

    // launching a relay session
    let mut session = Session::new(pgp_handler, zenoh_config.clone(), true, false);

    let _ = match session.serve().await {
        Ok(_) => {}
        Err(e) => match e {
            MessagingError::ZenohError => {
                println!("Something went wrong with the communication protocol. Check the configuration from Zenoh.");
                println!("Review your Zenoh configuration file '{}':", zenoh_config);
                let contents = fs::read_to_string(zenoh_config)
                    .expect("Something went wrong reading the file");
                println!("{}", contents);
                println!(
                    "Are you perhaps offline, or trying to reach a non-existing Zenoh router?"
                );
            }
            _ => {}
        },
    };
}
