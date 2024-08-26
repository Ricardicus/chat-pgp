#![allow(dead_code)]
mod session;

use session::crypto::{
    ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalID, PGPEnCryptOwned, PGPEnDeCrypt,
};
use session::messages::MessageData::Discovery;
use session::messages::{
    ChatMsg, DiscoveryMsg, EncryptedMsg, InitMsg, MessageData, MessageListener, Messageble,
    MessagebleTopicAsync, SessionMessage,
};
use session::protocol::*;
use session::Session;
use std::process::exit;
use std::thread;
use zenoh::prelude::r#async::*;
use zenoh::prelude::*;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use std::env;
use std::io::{self, Write};

use once_cell::sync::Lazy;

mod util;

mod pgp;
use pgp::pgp::{generate_new_key, get_public_key_as_base64, read_from_gpg, read_from_vec};

use clap::Parser;
use ncurses::*;

mod terminal;
use terminal::WindowManager;

use session::middleware::{ZMQHandler, ZenohHandler};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[clap(short, long)]
    #[arg(default_value = "new")]
    gpgkey: String,

    #[clap(long)]
    #[arg(default_value_t = ("127.0.0.1:5555").to_string())]
    server: String,

    #[clap(long)]
    #[arg(default_value = "false")]
    sub: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    test_receiver: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    test_sender: bool,

    #[clap(short, long)]
    #[arg(default_value = "zenoh/config.json5")]
    zenoh_config: String,
}

// Create a global instance of WindowManager
static WINDOW_MANAGER: Lazy<WindowManager> = Lazy::new(|| {
    let manager = WindowManager::init(2);
    manager
});

fn test_cb_chat(public_key: &str, message: &str) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            WINDOW_MANAGER.printw(
                0,
                &format!(
                    "{} ({}): {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid(),
                    message
                ),
            );
        }
        _ => {}
    }
}

fn test_cb_chat_input(
    _pub_key_fingerprint: &str,
    session_id: &str,
    topic_out: &str,
) -> (String, String) {
    let prompt = ">> ".to_string();
    let input = WINDOW_MANAGER.getch(1, &prompt);
    let input = input.trim();
    let topic = Topic::Internal.as_str();
    let msg = SessionMessage::new_internal(
        session_id.to_string(),
        input.to_string(),
        topic_out.to_string(),
    );
    (topic.to_string(), msg.serialize().unwrap())
}

fn test_cb_discovered(public_key: &str) -> bool {
    let mut shall_initialize = false;
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            WINDOW_MANAGER.printw(
                1,
                &format!(
                    "-- Discovered public key {} from {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid()
                ),
            );
            WINDOW_MANAGER.printw(1, "Do you want to chat with this peer? [y/n]");
            let input = WINDOW_MANAGER.getch(1, ">> ");
            if input.to_lowercase().starts_with('y') {
                shall_initialize = true;
            }
        }
        _ => {}
    }
    shall_initialize
}

fn test_cb_initialized(public_key: &str) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            WINDOW_MANAGER.printw(
                0,
                &format!("-- Initialized chat with {}", pub_encro.get_userid()),
            );
            WINDOW_MANAGER.printw(
                1,
                &format!("-- Initialized chat with {}", pub_encro.get_userid()),
            );
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut server = "tcp://".to_string();
    server.push_str(&cli.server);
    let gpgkey = cli.gpgkey;
    let sub = cli.sub;
    let test_sender = cli.test_sender;
    let test_receiver = cli.test_receiver;
    let zenoh_config = cli.zenoh_config;

    let mut cert = None;

    // check if gpgkey == "new"
    if gpgkey == "new" {
        cert = Some(generate_new_key().unwrap());
    }

    let mut passphrase = String::new();
    if cert.is_none() && gpgkey.len() > 0 {
        // Starct curses mode
        initscr();
        noecho();

        addstr(format!("Passphrase for gpgkey {}: ", gpgkey).as_str());
        refresh();

        getstr(&mut passphrase);

        echo();
        endwin();

        cert = Some(
            read_from_gpg(&gpgkey, Some(passphrase.as_str())).expect("Failed to read gpg key"),
        );
    }
    let cert = cert.unwrap();

    println!("pub_key: {}", cert.fingerprint());

    let pgp_handler = PGPEnDeCrypt::new(&cert, &passphrase);
    let pub_key_fingerprint = pgp_handler.get_public_key_fingerprint();
    let pub_key_full = pgp_handler.get_public_key_as_base64();

    let mut session = Session::new(pgp_handler, zenoh_config.clone());

    session.register_callback_chat(Box::new(test_cb_chat)).await;
    session
        .register_callback_initialized(Box::new(test_cb_initialized))
        .await;
    session
        .register_callback_discovered(Box::new(test_cb_discovered))
        .await;
    session
        .register_callback_chat_input(Box::new(test_cb_chat_input))
        .await;
    let zenoh_config = Config::from_file(zenoh_config).unwrap();

    if test_receiver {
        println!("-- Testing initiailize session [receiver]");
        session.serve_testing().await;
        exit(0);
    }

    if test_sender {
        println!("-- Testing initiailize session [sender]");
        let mut pub_key = None;

        let discovered_pub_keys = session.discover().await;
        if discovered_pub_keys.len() > 0 {
            pub_key = Some(discovered_pub_keys[0].clone());
        }

        let pub_key: String = pub_key.expect("Failed to discover nodes out there.. exiting..");
        let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
        let discovered_cert =
            read_from_vec(&pub_key_dec).expect("Got invalid certificate from discovery");
        let discovered_pub_key_fingerprint = discovered_cert.fingerprint().to_string();

        println!("Discovered pub_key: {}", &discovered_pub_key_fingerprint);
        let session_id = match session.initialize_session_zenoh(pub_key.clone()).await {
            Ok(ok) => {
                println!("-- Successfully established a session connection");
                exit(0);
            }
            Err(not_ok) => {
                println!("{}", not_ok);
                println!("error: Failed to initiailize a session.");
                exit(1);
            }
        };
    }

    let mut i = 0;
    WINDOW_MANAGER.printw(1, &format!("-- Using key {}", &pub_key_fingerprint));
    WINDOW_MANAGER.printw(1, &format!("-- Awaiting peer to connect..."));
    if !sub {
        WINDOW_MANAGER.printw(1, "-- Discovering peers...");
        session.discover().await;
    }
    session.serve().await;
}
