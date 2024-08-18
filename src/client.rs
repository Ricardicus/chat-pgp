#![allow(dead_code)]
mod session;

use session::crypto::{ChaCha20Poly1305EnDeCrypt, Cryptical, PGPEnDeCrypt};
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

mod util;

mod pgp;
use pgp::pgp::{generate_new_key, get_public_key_as_base64, read_from_gpg, read_from_vec};

use clap::Parser;
use ncurses::*;

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

fn test_cb(topic: &str, message: &str) {
    println!("{} - {}", topic, message);
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

    if gpgkey.len() > 0 {
        let mut cert = None;

        // check if gpgkey == "new"
        if gpgkey == "new" {
            cert = Some(generate_new_key().unwrap());
        }

        let mut passphrase = String::new();
        if cert.is_none() {
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

        let mut session = Session::new(pgp_handler, zenoh_config.clone());

        session.register_rx_local_callback(Box::new(test_cb)).await;
        let zenoh_config = Config::from_file(zenoh_config).unwrap();

        if test_receiver {
            println!("-- Testing initiailize session [receiver]");
            session.serve_testing().await;
            exit(0);
        }

        if test_sender {
            println!("-- Testing initiailize session [sender]");
            let discover_topic = Topic::Discover.as_str();
            let mut discover_topic_reply = discover_topic.to_string();
            discover_topic_reply.push_str(Topic::reply_suffix());
            let timeout_discovery = Duration::from_secs(5);

            let zenoh_session =
                Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
            let handler = ZenohHandler::new(zenoh_session);
            let mut cont = true;
            let mut attempts = 0;
            let maxattempts = 10;
            let mut pub_key = None;
            while attempts < maxattempts && cont {
                let msg = SessionMessage::new_discovery(pub_key_fingerprint.clone());
                match session
                    .send_and_multi_receive_topic(
                        msg,
                        discover_topic,
                        &discover_topic_reply,
                        timeout_discovery,
                        &handler,
                    )
                    .await
                {
                    Ok(msgs) => {
                        if msgs.len() == 0 {
                            attempts += 1;
                        }
                        for msg in msgs {
                            match msg.message {
                                Discovery(disc_msg) => {
                                    println!(
                                        "Discovered a node with pub_key: {}",
                                        &disc_msg.pub_key
                                    );
                                    cont = false;
                                    if pub_key.is_none() {
                                        pub_key = Some(disc_msg.pub_key);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {
                        if attempts >= maxattempts {
                            println!("Failed to discover any nodes out there.. exiting.");
                            exit(1);
                        } else {
                            attempts += 1;
                            thread::sleep(Duration::from_secs(3));
                        }
                    }
                };
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

        if sub {
            println!("Awaiting for someone to initiailize a session...");
            session.serve_with_chat().await;
        } else {
            let discover_topic = Topic::Discover.as_str();
            let mut discover_topic_reply = discover_topic.to_string();
            discover_topic_reply.push_str(Topic::reply_suffix());
            let timeout_discovery = Duration::from_secs(5);

            let zenoh_session =
                Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
            let handler = ZenohHandler::new(zenoh_session);
            let mut cont = true;
            let mut attempts = 0;
            let mut pub_key = None;
            while attempts < 10 && cont {
                let msg = SessionMessage::new_discovery(pub_key_fingerprint.clone());
                match session
                    .send_and_multi_receive_topic(
                        msg,
                        discover_topic,
                        &discover_topic_reply,
                        timeout_discovery,
                        &handler,
                    )
                    .await
                {
                    Ok(msgs) => {
                        if msgs.len() == 0 {
                            attempts += 1;
                        }
                        for msg in msgs {
                            match msg.message {
                                Discovery(disc_msg) => {
                                    println!(
                                        "Discovered a node with pub_key: {}",
                                        &disc_msg.pub_key
                                    );
                                    cont = false;
                                    if pub_key.is_none() {
                                        pub_key = Some(disc_msg.pub_key);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {
                        println!("Failed to discover any nodes out there.. exiting.");
                        exit(1);
                    }
                };
            }

            let pub_key: String = pub_key.expect("Failed to discover nodes out there.. exiting..");
            let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
            let discovered_cert =
                read_from_vec(&pub_key_dec).expect("Got invalid certificate from discovery");
            let discovered_pub_key_fingerprint = discovered_cert.fingerprint().to_string();

            println!("Discovered pub_key: {}", &discovered_pub_key_fingerprint);
            let session_id = match session.initialize_session_zenoh(pub_key.clone()).await {
                Ok(ok) => ok,
                Err(not_ok) => {
                    println!("{}", not_ok);
                    println!("error: Failed to initiailize a session.");
                    exit(1);
                }
            };

            session
                .chat(session_id.clone(), &discovered_pub_key_fingerprint, false)
                .await;
            session.serve().await;
        }
    }
}
