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
use std::pin::Pin;

use std::future::Future;

use once_cell::sync::Lazy;

mod util;

mod pgp;
use pgp::pgp::{generate_new_key, get_public_key_as_base64, read_from_gpg, read_from_vec};

extern crate sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;

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
static mut PIPE_WIN0: Lazy<WindowPipe> = Lazy::new(|| WindowPipe::new());
static mut PIPE_WIN1: Lazy<WindowPipe> = Lazy::new(|| WindowPipe::new());

async fn println_message(window: usize, message: String) {
    if window == 0 {
        unsafe {
            PIPE_WIN0
                .send(WindowCommand::Println(PrintCommand { window, message }))
                .await;
        }
    } else {
        unsafe {
            PIPE_WIN1
                .send(WindowCommand::Println(PrintCommand { window, message }))
                .await;
        }
    }
}
async fn print_message(window: usize, message: String) {
    if window == 0 {
        unsafe {
            PIPE_WIN0
                .send(WindowCommand::Print(PrintCommand { window, message }))
                .await;
        }
    } else {
        unsafe {
            PIPE_WIN1
                .send(WindowCommand::Print(PrintCommand { window, message }))
                .await;
        }
    }
}
async fn read_message(window: usize, prompt: &str) -> Result<String, ()> {
    let mut input = Err(());
    if window == 0 {
        unsafe {
            input = PIPE_WIN0.get_input(window, prompt).await;
        }
    } else {
        unsafe {
            input = PIPE_WIN1.get_input(window, prompt).await;
        }
    }
    input
}
async fn println_message_str(window: usize, message: &str) {
    println_message(window, message.to_string()).await;
}
async fn print_message_str(window: usize, message: &str) {
    print_message(window, message.to_string()).await;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ListCommand {}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct HelpCommand {}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct InitializeCommand {
    pub entry: usize,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ExitCommand {}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum InputCommand {
    List(ListCommand),
    Initialize(InitializeCommand),
    Exit(ExitCommand),
    Help(HelpCommand),
}

impl InputCommand {
    fn parse_from(input: &str) -> Option<Self> {
        let binding = input.to_lowercase();
        let mut parts = binding.split_whitespace();
        match parts.next() {
            Some("!list") => {
                let cmd = ListCommand {};
                Some(InputCommand::List(cmd))
            }
            Some("!init") => {
                let entry = match parts.next() {
                    Some(entry) => entry.parse::<usize>().unwrap(),
                    None => 0,
                };
                let cmd = InitializeCommand { entry };
                Some(InputCommand::Initialize(cmd))
            }
            Some("!exit") => {
                let cmd = ExitCommand {};
                Some(InputCommand::Exit(cmd))
            }
            Some("!help") => {
                let cmd = HelpCommand {};
                Some(InputCommand::Help(cmd))
            }
            _ => None,
        }
    }

    async fn print_help() {
        let mut help_text = String::new();
        println_message_str(1, "Available commands:").await;
        println_message_str(1, "!list").await;
        println_message_str(1, "- List and enumerate all discovered peers.").await;
        println_message_str(1, "!init [entry]").await;
        println_message_str(1, "- Initialize a chat session with a peer").await;
        println_message_str(1, "  enumerated as per !list.").await;
        println_message_str(1, "!exit").await;
        println_message_str(1, "- Exit the program.").await;
    }
    async fn print_small_help() {
        println_message_str(1, "Type !exit to exit and !help for more commands.").await;
    }
    async fn read_yes_or_no(window: usize, prompt: &str) -> Result<bool, ()> {
        let input = read_message(window, prompt).await;
        match input {
            Ok(input) => {
                if input.to_lowercase().starts_with('y') {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Err(()),
        }
    }
}

async fn cb_chat(public_key: String, message: String) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            println_message(
                0,
                format!(
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

async fn cb_chat_input(
    _pub_key_fingerprint: String,
    session_id: String,
    topic_out: String,
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

async fn cb_discovered(public_key: String) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => true,
        _ => false,
    }
}

async fn cb_terminate() {
    println_message(1, format!("-- Terminating session ..."));
}

async fn cb_initialized(public_key: String) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            /*println_message(
                1,
                format!(
                    "-- Initialization attempt with {} {}",
                    pub_encro.get_public_key_fingerprint(),
                    pub_encro.get_userid()
                ),
            )
            .await;
            println_message(
                1,
                format!("The peer wants to chat, do you want to chat with this peer? [y/n]"),
            )
            .await;

            let response = InputCommand::read_yes_or_no(1, ">> ").await;
            if response.is_err() {
                println_message(
                    1,
                    format!("-- Failed to read input.. Not initializing chat"),
                )
                .await;
                return false;
            } else {
                let go_further = response.unwrap();
                if go_further {
                    println_message(
                        1,
                        format!(
                            "-- Initializing chat with {} ({})",
                            pub_encro.get_userid(),
                            pub_encro.get_public_key_fingerprint()
                        ),
                    )
                    .await;
                    return true;
                } else {
                    println_message(
                        1,
                        format!(
                            "-- Chat not initialized with {} ({})",
                            pub_encro.get_userid(),
                            pub_encro.get_public_key_fingerprint()
                        ),
                    )
                    .await;
                }
            }
            false*/
            true
        }
        _ => {
            &format!("-- Chat was not initiailized");
            false
        }
    }
}

async fn terminate(session_tx: mpsc::Sender<(String, String)>) {
    let pipe0;
    unsafe {
        pipe0 = PIPE_WIN0.clone();
    }
    let pipe1;
    unsafe {
        pipe1 = PIPE_WIN1.clone();
    }
    let topic = Topic::Internal.as_str();
    let msg = SessionMessage::new_internal(
        "internal".to_owned(),
        "terminate".to_owned(),
        topic.to_string(),
    );
    pipe0.send(WindowCommand::Shutdown()).await;
    pipe1.send(WindowCommand::Shutdown()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    session_tx
        .send((topic.to_string(), msg.serialize().unwrap()))
        .await;
}

async fn terminal_program(
    session_tx: mpsc::Sender<(String, String)>,
    cert: Arc<Cert>,
    mut session: Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>,
) {
    let mut userid = String::new();
    for uid in cert.userids() {
        userid.push_str(&uid.userid().to_string());
    }
    println_message(
        1,
        format!("-- Using key {} {}", &cert.fingerprint(), userid),
    )
    .await;
    // Serve incoming commands
    InputCommand::print_small_help().await;
    let mut keep_running = true;
    let mut print_prompt = true;
    while keep_running {
        if print_prompt {
    print_message_str(1, ">> ").await;
        }
        let input = read_message(1, "").await;
        print_prompt = true;
        if input.is_ok() {
            let cmd = InputCommand::parse_from(&input.unwrap());
            match cmd {
                Some(InputCommand::List(_)) => {
                    // List all discovered peers
                    let discovered = session.get_discovered().await;
                    let mut i = 1;
                    for peer in discovered {
                        let peer_decoded = base64::decode(&peer).unwrap();
                        let peer_cert = read_from_vec(&peer_decoded).unwrap();
                        let peer_fingerprint = peer_cert.fingerprint();
                        let mut peer_userid = "".to_string();
                        for uid in peer_cert.userids() {
                            peer_userid.push_str(&uid.userid().to_string());
                        }
                        println_message(
                            1,
                            format!("-- {}: {} {}", i, peer_userid, peer_fingerprint),
                        )
                        .await;
                        i += 1;
                    }
                }
                Some(InputCommand::Initialize(cmd)) => {
                    // Initialize a chat session
                    let entry = cmd.entry;
                    let discovered = session.get_discovered().await;

                    if entry < 1 || entry > discovered.len() {
                        println_message(1, format!("-- Invalid entry {}", entry)).await;
                    } else {
                        let peer = discovered[entry - 1].clone();
                        let peer_decoded = base64::decode(&peer).unwrap();
                        let peer_cert = read_from_vec(&peer_decoded).unwrap();
                        let peer_fingerprint = peer_cert.fingerprint();
                        let mut peer_userid = "".to_string();
                        for uid in peer_cert.userids() {
                            peer_userid.push_str(&uid.userid().to_string());
                        }
                        println_message(
                            1,
                            format!(
                                "-- Do you want to initialize chat with {} ({})? [y/N]",
                                peer_userid, peer_fingerprint
                            ),
                        )
                        .await;
                        let response = InputCommand::read_yes_or_no(1, ">> ").await;
                        if response.is_err() {
                        } else {
                            let go_further = response.unwrap();
                            if go_further {
                                println_message(
                                    1,
                                    format!(
                                        "-- Initializing chat with {} ({})",
                                        peer_userid, peer_fingerprint
                                    ),
                                )
                                .await;
                                let session_id =
                                    match session.initialize_session_zenoh(peer.clone()).await {
                                        Ok(ok) => {
                                            println!(
                                                "-- Successfully established a session connection"
                                            );
                                        }
                                        Err(not_ok) => {
                                            println!("{}", not_ok);
                                            println!("error: Failed to initiailize a session.");
                                        }
                                    };
                            } else {
                                println_message(
                                    1,
                                    format!(
                                        "-- Chat not initialized with {} ({})",
                                        peer_userid, peer_fingerprint
                                    ),
                                )
                                .await;
                            }
                        }
                    }
                }
                Some(InputCommand::Exit(_)) => {
                    // Exit the program
                    keep_running = false;
                    terminate(session_tx.clone()).await;
                }
                Some(InputCommand::Help(_)) => {
                    // Print help
                    InputCommand::print_help().await;
                }
                None => {
                    print_prompt = false;
                }
            }
        } else {
        }
    }
}

async fn launch_terminal_program(
    cert: Arc<Cert>,
    session_tx: mpsc::Sender<(String, String)>,
    session: Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>,
) {
    let pipe0;
    unsafe {
        pipe0 = PIPE_WIN0.clone();
    }
    let pipe1;
    unsafe {
        pipe1 = PIPE_WIN1.clone();
    }
    // Setup window manager serving
    tokio::spawn(async move {
        let mut window_manager = WindowManager::new();

        let (tx, rx) = mpsc::channel::<String>(50);

        let pipe_clone = pipe0.clone();
        let tx_clone = tx.clone();

        let tx_clone = tx_clone.clone();
        window_manager.serve(pipe_clone).await;
    });
    tokio::spawn(async move {
        let mut window_manager = WindowManager::new();

        let (tx, rx) = mpsc::channel::<String>(50);

        let pipe_clone = pipe1.clone();
        let tx_clone = tx.clone();

        let tx_clone = tx_clone.clone();
        window_manager.serve(pipe_clone).await;
    });
    let pipe0;
    unsafe {
        pipe0 = PIPE_WIN0.clone();
    }
    let pipe1;
    unsafe {
        pipe1 = PIPE_WIN1.clone();
    }

    // Initialize
    println!("Initializing ");
    pipe0.send(WindowCommand::Init()).await;

    tokio::time::sleep(Duration::from_millis(400)).await;

    let pgp_handler = PGPEnDeCrypt::new_no_certpass(cert.clone());
    let pub_key_fingerprint = pgp_handler.get_public_key_fingerprint();
    let pub_key_userid = pgp_handler.get_userid();
    let pub_key_full = pgp_handler.get_public_key_as_base64();

    let (max_y, max_x) = WindowManager::get_max_yx();
    let num_windows = 2;
    let win_height = max_y / num_windows as i32;
    let win_width = max_x;

    // Create the windows
    for i in 0..num_windows {
        let start_y = i * win_height;
        let window_cmd = NewWindowCommand {
            win_number: i as usize,
            start_y,
            win_height,
            win_width,
        };
        if i == 0 {
            pipe0.send(WindowCommand::New(window_cmd)).await;
        } else {
            pipe1.send(WindowCommand::New(window_cmd)).await;
        }
    }

    tokio::time::sleep(Duration::from_millis(600)).await;

    let pipe0;
    unsafe {
        pipe0 = PIPE_WIN0.clone();
    }
    // Launch window manager program
    tokio::spawn(async move {
        // Wait for the window manager loops to be set up
        tokio::time::sleep(Duration::from_millis(400)).await;
        terminal_program(session_tx, cert, session).await;
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

    let pgp_handler = PGPEnDeCrypt::new(cert.clone(), &passphrase);
    let pub_key_fingerprint = pgp_handler.get_public_key_fingerprint();
    let pub_key_userid = pgp_handler.get_userid();
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

    // Wrap the async functions into a closure that matches the signature
    let callback_discovered = move |arg1: String| {
        Box::pin(cb_discovered(arg1)) as Pin<Box<dyn Future<Output = bool> + Send>>
    };
    let callback_chat = move |arg1: String, arg2: String| {
        Box::pin(cb_chat(arg1, arg2)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_initialized = move |arg1: String| {
        Box::pin(cb_initialized(arg1)) as Pin<Box<dyn Future<Output = bool> + Send>>
    };
    let callback_chat_input = move |arg1: String, arg2: String, arg3: String| {
        Box::pin(cb_chat_input(arg1, arg2, arg3))
            as Pin<Box<dyn Future<Output = (String, String)> + Send>>
    };
    let callback_terminate =
        move || Box::pin(cb_terminate()) as Pin<Box<dyn Future<Output = ()> + Send>>;

    // Register the async callback
    session
        .register_callback_chat(Box::new(callback_chat))
        .await;
    session
        .register_callback_initialized(Box::new(callback_initialized))
        .await;
    session
        .register_callback_discovered(Box::new(callback_discovered))
        .await;
    session
        .register_callback_chat_input(Box::new(callback_chat_input))
        .await;
    session
        .register_callback_terminate(Box::new(callback_terminate))
        .await;

    let mut i = 0;

    let tx = session.get_tx().await;
    tokio::spawn(async move {
        let c = tokio::signal::ctrl_c().await;
        if c.is_ok() {
            terminate(tx).await;
        }
    });

    launch_terminal_program(cert.clone(), session.get_tx().await, session.clone()).await;

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

    tokio::time::sleep(Duration::from_millis(400)).await;
    session.serve().await;
}
