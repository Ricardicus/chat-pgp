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
use zenoh::Config;

use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

use std::env;
use std::io::{self, Write};

use once_cell::sync::Lazy;

mod util;

mod pgp;
use pgp::pgp::{generate_new_key, get_public_key_as_base64, read_from_gpg, read_from_vec};

use clap::Parser;
use ncurses::*;

mod terminal;
use terminal::{
    NewWindowCommand, PrintCommand, ReadCommand, WindowCommand, WindowManager, WindowPipe,
};

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
    test_receiver: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    no_discovery: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    test_sender: bool,

    #[clap(short, long)]
    #[arg(default_value = "zenoh/config.json5")]
    zenoh_config: String,
}

// Create a global instance of WindowManager
static mut WINDOW_PIPE: Lazy<WindowPipe> = Lazy::new(|| WindowPipe::new());

async fn print_message(window: usize, message: String) {
    unsafe {
        WINDOW_PIPE
            .send(WindowCommand::Print(PrintCommand { window, message }))
            .await;
    }
}

fn cb_chat(public_key: &str, message: &str) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            /*WINDOW_MANAGER.printw(
                0,
                &format!(
                    "{} ({}): {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid(),
                    message
                ),
            );*/
        }
        _ => {}
    }
}

fn cb_chat_input(
    _pub_key_fingerprint: &str,
    session_id: &str,
    topic_out: &str,
) -> (String, String) {
    let prompt = ">> ".to_string();
    //let input = WINDOW_MANAGER.getch(1, &prompt);
    let input = "".to_string(); // input.trim();
    let topic = Topic::Internal.as_str();
    let mut msg = SessionMessage::new_internal(
        session_id.to_string(),
        input.to_string(),
        topic_out.to_string(),
    );
    if input == "!exit" {
        // Special message that terminate the session
        msg = SessionMessage::new_internal(
            "internal".to_owned(),
            "terminate".to_owned(),
            topic.to_string(),
        );
    }
    return (topic.to_string(), msg.serialize().unwrap());
}

fn cb_discovered(public_key: &str) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            /*  WINDOW_MANAGER.printw(
                1,
                &format!(
                    "-- Discovered public key {} from {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid()
                ),
            );*/
            true
        }
        _ => false,
    }
}

fn cb_terminate() {
    //WINDOW_MANAGER.printw(1, "-- Terminating session...");
    //WINDOW_MANAGER.cleanup();
}

fn cb_initialized(public_key: &str) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            /*WINDOW_MANAGER.printw(
                1,
                &format!(
                    "-- Initialization attempt with {} {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid()
                ),
            );
            WINDOW_MANAGER.printw(
                1,
                "The peer wants to chat, do you want to chat with this peer? [y/n]",
            );
            let input = WINDOW_MANAGER.getch(1, ">> ");
            if input.to_lowercase().starts_with('y') {
                WINDOW_MANAGER.printw(1, "-- Chat initialized, exit by typing '!exit'");
                return true;
            } else {
                WINDOW_MANAGER.printw(1, "-- chat not accepted");
            }*/
            false
        }
        _ => {
            &format!("-- Chat was not initiailized");
            false
        }
    }
}

async fn terminate(tx: mpsc::Sender<(String, String)>) {
    let pipe;
    unsafe {
        pipe = WINDOW_PIPE.clone();
    }
    let topic = Topic::Internal.as_str();
    let msg = SessionMessage::new_internal(
        "internal".to_owned(),
        "terminate".to_owned(),
        topic.to_string(),
    );
    pipe.send(WindowCommand::Shutdown()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    tx.send((topic.to_string(), msg.serialize().unwrap())).await;
}

async fn launch_terminal_program() {
    tokio::spawn(async move {
        let pipe;
        unsafe {
            pipe = WINDOW_PIPE.clone();
        }
        let mut window_manager = WindowManager::new();

        let (tx, rx) = mpsc::channel::<String>(50);

        let pipe_clone = pipe.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            // Initialize
            let pipe = pipe_clone;
            pipe.send(WindowCommand::Init()).await;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let (max_y, max_x) = WindowManager::get_max_yx();
            let num_windows = 2;
            let win_height = max_y / num_windows as i32;
            let win_width = max_x;

            // Create the windows
            for i in 0..num_windows {
                let start_y = i * win_height;
                let window_cmd = NewWindowCommand {
                    start_y,
                    win_height,
                    win_width,
                };
                pipe.send(WindowCommand::New(window_cmd)).await;
            }
        });
        let tx_clone = tx_clone.clone();
        let pipe_clone = pipe.clone();
        window_manager.serve(pipe_clone).await;
    });
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut server = "tcp://".to_string();
    server.push_str(&cli.server);
    let gpgkey = cli.gpgkey;
    let test_sender = cli.test_sender;
    let test_receiver = cli.test_receiver;
    let zenoh_config = cli.zenoh_config;
    let no_discovery = cli.no_discovery;

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
    let cert = Arc::new(cert.unwrap());

    let pgp_handler = PGPEnDeCrypt::new(cert, &passphrase);
    let pub_key_fingerprint = pgp_handler.get_public_key_fingerprint();
    let pub_key_full = pgp_handler.get_public_key_as_base64();

    let mut session = Session::new(pgp_handler, zenoh_config.clone());

    let zenoh_config = Config::from_file(zenoh_config).unwrap();

    if test_receiver {
        println!("-- Testing initiailize session [receiver]");
        session.serve_testing().await;
        exit(0);
    }

    if test_sender {
        println!("-- Testing initiailize session [sender]");
        /*
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
        */
    }

    session.register_callback_chat(Box::new(cb_chat)).await;
    session
        .register_callback_initialized(Box::new(cb_initialized))
        .await;
    session
        .register_callback_discovered(Box::new(cb_discovered))
        .await;
    session
        .register_callback_chat_input(Box::new(cb_chat_input))
        .await;
    session
        .register_callback_terminate(Box::new(cb_terminate))
        .await;

    let mut i = 0;

    let tx = session.get_tx().await;
    tokio::spawn(async move {
        let c = tokio::signal::ctrl_c().await;
        if c.is_ok() {
            terminate(tx).await;
        }
    });

    launch_terminal_program().await;

    tokio::time::sleep(Duration::from_secs(1)).await;

    print_message(1, format!("-- Using key {}", &pub_key_fingerprint)).await;
    /*
    if !no_discovery {
        WINDOW_MANAGER.printw(1, "-- Discovering other peers out there...");
        session.discover().await;

        let mut session_discover = session.clone();
        session_discover.set_tx_chat(session.get_tx().await);
        tokio::spawn(async move {
            let mut session = session_discover;
            let mut continue_search = true;
            let mut keep_running = true;
            unsafe {
                keep_running = *KEEP_RUNNING;
            }
            let mut peers = Vec::new();
            while continue_search && keep_running {
                session.discover().await;

                WINDOW_MANAGER.printw(1, "-- Awaiting responses...");
                // sleep for some time
                tokio::time::sleep(Duration::from_secs(5)).await;

                peers = session.get_discovered().await;
                if peers.len() == 0 {
                    WINDOW_MANAGER.printw(
                        1,
                        "-- Did not discover any other peers out there ¯\\_(´_´)_/¯...",
                    );
                    WINDOW_MANAGER.printw(1, &format!("-- Do you want to search again? [y/n]"));

                    let input = WINDOW_MANAGER.getch(1, ">> ");
                    if input.to_lowercase().starts_with('y') {
                        continue_search = true;
                    } else {
                        continue_search = false;
                    }
                } else {
                    continue_search = false;
                }
            }
            if peers.len() > 0 {
                WINDOW_MANAGER.printw(1, &format!("-- Discovered {} peers", peers.len()));
                let mut i = 1;
                for peer in &peers {
                    let peer_decoded = base64::decode(&peer).unwrap();
                    let peer_cert = read_from_vec(&peer_decoded).unwrap();
                    let peer_fingerprint = peer_cert.fingerprint();
                    let mut peer_userid = "".to_string();
                    for uid in peer_cert.userids() {
                        peer_userid.push_str(&uid.userid().to_string());
                    }

                    WINDOW_MANAGER.printw(
                        1,
                        &format!("-- {}: {} {}", i, peer_userid, peer_fingerprint),
                    );
                    i += 1;
                }

                let mut keep_going = true;
                let mut keep_running = true;
                while keep_running && keep_going {
                    unsafe {
                        keep_running = *KEEP_RUNNING;
                    }
                    WINDOW_MANAGER.printw(
                        1,
                        &format!(
                            "Which peer do you want to connect to [{}]?",
                            if peers.len() == 1 {
                                format!("1")
                            } else {
                                format!("1-{}", peers.len())
                            }
                        ),
                    );
                    let p = WINDOW_MANAGER.getch(1, ">> ");
                    if p.to_lowercase().starts_with('y') {
                        let p = 1;
                        let peer = peers[p - 1].clone();
                        let peer_decoded = base64::decode(&peer).unwrap();
                        let peer_cert = read_from_vec(&peer_decoded).unwrap();
                        let peer_fingerprint = peer_cert.fingerprint();
                        let mut peer_userid = "".to_string();
                        for uid in peer_cert.userids() {
                            peer_userid.push_str(&uid.userid().to_string());
                        }
                        WINDOW_MANAGER.printw(
                            1,
                            &format!(
                                "-- Sending a session initialization request to {} {} ...",
                                peer_userid, peer_fingerprint
                            ),
                        );
                        let session_id = session.initialize_session_zenoh(peer).await.unwrap();
                        keep_going = false;
                    }
                    match p.parse::<usize>() {
                        Ok(p) => {
                            if p > 0 && p <= peers.len() {
                                let peer = peers[p - 1].clone();
                                let peer_decoded = base64::decode(&peer).unwrap();
                                let peer_cert = read_from_vec(&peer_decoded).unwrap();
                                let peer_fingerprint = peer_cert.fingerprint();
                                let mut peer_userid = "".to_string();
                                for uid in peer_cert.userids() {
                                    peer_userid.push_str(&uid.userid().to_string());
                                }
                                WINDOW_MANAGER.printw(
                                    1,
                                    &format!(
                                        "-- Sending a session initialization request to {} {} ...",
                                        peer_userid, peer_fingerprint
                                    ),
                                );
                                let session_id =
                                    session.initialize_session_zenoh(peer).await.unwrap();
                                keep_going = false;
                            } else {
                                WINDOW_MANAGER.printw(1, "-- Invalid input");
                                keep_going = true;
                            }
                        }
                        Err(_) => {
                            WINDOW_MANAGER.printw(1, "-- Invalid input");
                            keep_going = true;
                        }
                    }
                }
            }
        });
    }
    WINDOW_MANAGER.printw(1, &format!("-- Awaiting other peers to connect to us..."));*/
    session.serve().await;
}
