#![allow(dead_code)]
mod session;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use session::crypto::{
    ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalID, PGPEnCryptOwned, PGPEnDeCrypt,
};
use session::messages::{MessagingError, SessionMessage};
use session::protocol::*;
use session::Session;
use std::fs;
use std::future::Future;

use std::pin::Pin;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

mod util;
use util::get_current_datetime;

mod pgp;
use pgp::pgp::{generate_new_key, read_from_gpg, read_from_vec};

extern crate sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;

use clap::Parser;
use ncurses::*;

mod terminal;
use terminal::{
    NewWindowCommand, PrintCommand, WindowCommand, WindowManager, WindowPipe,
};



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
async fn read_message(
    window: usize,
    prompt: &str,
    upper_prompt: &str,
    timeout: i32,
) -> Result<String, ()> {
    let mut input = Err(());
    if window == 0 {
        unsafe {
            input = PIPE_WIN0
                .get_input(window, prompt, upper_prompt, timeout)
                .await;
        }
    } else {
        unsafe {
            input = PIPE_WIN1
                .get_input(window, prompt, upper_prompt, timeout)
                .await;
        }
    }
    input
}
async fn read_chat_message(window: usize) -> Result<Option<String>, ()> {
    let mut input = Err(());
    if window == 0 {
        unsafe {
            input = PIPE_WIN0.get_chat_input().await;
        }
    } else {
        unsafe {
            input = PIPE_WIN1.get_chat_input().await;
        }
    }
    input
}
async fn send_chat_message(window: usize, message: Option<String>) {
    if window == 0 {
        unsafe {
            PIPE_WIN0.tx_chat_input(message).await;
        }
    } else {
        unsafe {
            PIPE_WIN1.tx_chat_input(message).await;
        }
    }
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
        let _help_text = String::new();
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
        println_message(1, InputCommand::get_small_help()).await;
    }
    fn get_small_help() -> String {
        "Type !exit to exit and !help for more commands.".to_string()
    }
    async fn read_yes_or_no(window: usize, prompt: &str) -> Result<bool, ()> {
        let input = read_message(window, prompt, "", 60).await;
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

fn short_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() > 8 {
        let first_four = &fingerprint[0..4];
        let last_four = &fingerprint[fingerprint.len() - 4..];
        format!("{}...{}", first_four, last_four)
    } else {
        fingerprint.to_string()
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
            let date_time = get_current_datetime();
            println_message(
                0,
                format!(
                    "{} - {} ({}): {}",
                    date_time,
                    pub_encro.get_userid(),
                    short_fingerprint(&pub_encro.get_public_key_fingerprint()),
                    message
                ),
            )
            .await;
        }
        _ => {}
    }
}

async fn cb_chat_input(
    _pub_key_fingerprint: String,
    session_id: String,
    topic_out: String,
) -> Option<(String, String)> {
    let _prompt = ">> ".to_string();
    let input = read_chat_message(1).await;
    if input.is_err() {
        return None;
    }
    let input = input.unwrap();
    if input.is_none() {
        return None;
    }
    let input = input.unwrap();
    let topic = Topic::Internal.as_str();
    let mut msg = SessionMessage::new_internal(
        session_id.to_string(),
        input.to_string(),
        topic_out.to_string(),
    );
    if input.len() == 0 {
        return None;
    }
    if input == "!exit" {
        // Special message that terminate the session
        msg = SessionMessage::new_internal(
            "internal".to_owned(),
            "terminate".to_owned(),
            topic.to_string(),
        );
    }
    return Some((topic.to_string(), msg.serialize().unwrap()));
}

async fn cb_closed(public_key: String, _session_id: String) {
    let pub_key_decoded = base64::decode(public_key);
    if pub_key_decoded.is_err() {
        return;
    }
    let pub_key_decoded = pub_key_decoded.unwrap();

    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            let userid = pub_encro.get_userid();
            let fingerprint = pub_encro.get_public_key_fingerprint();
            let fingerprint_short = short_fingerprint(&fingerprint);
            let date_and_time = get_current_datetime();

            println_message(
                0,
                format!(
                    "[{} - ** {} ({}) has terminated the chat session **]",
                    date_and_time, userid, fingerprint_short
                ),
            )
            .await;
        }
        _ => {}
    }
}

async fn cb_discovered(public_key: String) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(_pub_encro) => true,
        _ => false,
    }
}

async fn cb_terminate() {
    println_message(1, format!("-- Terminating session ...")).await;
}

async fn cb_init_declined(public_key: String, _message: String) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            println_message(
                1,
                format!(
                    "-- {} declined our chat request ¯\\_(´_´)_/¯...",
                    pub_encro.get_userid()
                ),
            )
            .await;
        }
        _ => {}
    }
}

async fn cb_init_await(public_key: String) {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            println_message(
                1,
                format!(
                    "-- Awaiting for {} to accept our request ...",
                    pub_encro.get_userid()
                ),
            )
            .await;
        }
        _ => {}
    }
}

async fn cb_init_accepted(_public_key: String) {
    println_message(
        1,
        format!("-- Peer accepted the connection. You can now chat!"),
    )
    .await;
}

async fn cb_init_incoming(public_key: String) -> bool {
    let pub_key_decoded = match base64::decode(public_key) {
        Err(_) => {
            return false;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(_pub_encro) => true,
        _ => {
            let _ = &format!("-- Chat was not initiailized");
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
    send_chat_message(1, None).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = session_tx
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
    let mut upper_prompt = format!("-- Using key {} {}", &cert.fingerprint(), userid);
    upper_prompt.push_str("\n");
    upper_prompt.push_str(&InputCommand::get_small_help());
    // Serve incoming commands
    InputCommand::print_small_help().await;
    let mut keep_running = true;
    let mut print_prompt = true;
    while keep_running {
        let pending = session.get_pending_request().await;
        if pending.is_some() {
            let pending = pending.unwrap();
            let session_data = pending;
            let pub_key = session_data.pub_key.clone();
            let session_id = session_data.id.clone();
            let pub_key_decoded = match base64::decode(pub_key) {
                Err(_) => Err(()),
                Ok(pub_key) => Ok(pub_key),
            };
            if pub_key_decoded.is_ok() {
                let pub_key_decoded = pub_key_decoded.unwrap();
                match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
                    Ok(pub_encro) => {
                        println_message_str(
                            1,
                            &format!(
                                "-- There is a chat initialization request sent from {} ({})",
                                pub_encro.get_userid(),
                                pub_encro.get_public_key_fingerprint()
                            ),
                        )
                        .await;
                        println_message_str(1, "-- Do you want to chat with this peer? [y/n]")
                            .await;
                        let r = InputCommand::read_yes_or_no(1, ">> ").await;
                        if r.is_ok() && r.unwrap() {
                            let _ = session.accept_pending_request(&session_id).await;
                            println_message_str(1, "-- Accepted this chat request.").await;

                            println_message_str(
                                1,
                                &format!(
                                    "-- You can now chat with {} ({})",
                                    pub_encro.get_userid(),
                                    pub_encro.get_public_key_fingerprint()
                                ),
                            )
                            .await;
                            print_prompt = true;
                        } else {
                            println_message_str(1, "-- Declined this chat request.").await;
                            let _ = session.decline_pending_request(&session_id).await;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            let input;
            if print_prompt {
                input = read_message(1, ">> ", &upper_prompt, 1).await;
            } else {
                input = read_message(1, "", &upper_prompt, 1).await;
            }
            if input.is_ok() {
                let input = input.unwrap();
                if input.len() > 0 {
                    print_prompt = true;
                } else {
                    print_prompt = false;
                }
                let cmd = InputCommand::parse_from(&input);
                match cmd {
                    Some(InputCommand::List(_)) => {
                        // List all discovered peers
                        let discovered = session.get_discovered().await;
                        let mut i = 1;
                        if discovered.len() == 0 {
                            println_message_str(
                                1,
                                "-- Did not discover any other peers out there ¯\\_(´_´)_/¯...",
                            )
                            .await;
                        } else {
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
                                    let _session_id = match session
                                        .initialize_session_zenoh(peer.clone())
                                        .await
                                    {
                                        Ok(_ok) => {}
                                        Err(not_ok) => {
                                            terminate(session_tx.clone()).await;
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
                        // Send this input to listeners
                        if input.len() > 0 && session.get_number_of_sessions().await > 0 {
                            send_chat_message(1, Some(input)).await;
                        }
                    }
                }
            } else {
                keep_running = false;
            }
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

        let pipe_clone = pipe0.clone();
        window_manager.serve(pipe_clone).await;
    });
    tokio::spawn(async move {
        let mut window_manager = WindowManager::new();

        let pipe_clone = pipe1.clone();
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
    pipe0.send(WindowCommand::Init()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let pgp_handler = PGPEnDeCrypt::new_no_certpass(cert.clone());
    let _pub_key_fingerprint = pgp_handler.get_public_key_fingerprint();
    let _pub_key_userid = pgp_handler.get_userid();
    let _pub_key_full = pgp_handler.get_public_key_as_base64();

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
    let mut session = Session::new(pgp_handler, zenoh_config.clone());

    if test_receiver {
        session.set_discovery_interval_seconds(1);
        let mut session_clone = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            session_clone.stop_session().await;
        });
        session.serve().await;
        let discovered = session.get_discovered().await;
        if discovered.len() > 0 {
            exit(0);
        }
        exit(1);
    }

    if test_sender {
        session.set_discovery_interval_seconds(1);

        let mut session_clone = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            session_clone.stop_session().await;
        });

        session.serve().await;
        let discovered = session.get_discovered().await;
        if discovered.len() > 0 {
            exit(0);
        }
        exit(1);
    }

    // Wrap the async functions into a closure that matches the signature
    let callback_discovered = move |arg1: String| {
        Box::pin(cb_discovered(arg1)) as Pin<Box<dyn Future<Output = bool> + Send>>
    };
    let callback_chat = move |arg1: String, arg2: String| {
        Box::pin(cb_chat(arg1, arg2)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_init_incoming = move |arg1: String| {
        Box::pin(cb_init_incoming(arg1)) as Pin<Box<dyn Future<Output = bool> + Send>>
    };
    let callback_init_await = move |arg1: String| {
        Box::pin(cb_init_await(arg1)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_init_accepted = move |arg1: String| {
        Box::pin(cb_init_accepted(arg1)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_init_declined = move |arg1: String, arg2: String| {
        Box::pin(cb_init_declined(arg1, arg2)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_session_close = move |arg1: String, arg2: String| {
        Box::pin(cb_closed(arg1, arg2)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };
    let callback_chat_input = move |arg1: String, arg2: String, arg3: String| {
        Box::pin(cb_chat_input(arg1, arg2, arg3))
            as Pin<Box<dyn Future<Output = Option<(String, String)>> + Send>>
    };
    let callback_terminate =
        move || Box::pin(cb_terminate()) as Pin<Box<dyn Future<Output = ()> + Send>>;

    // Register the async callback
    session
        .register_callback_chat(Box::new(callback_chat))
        .await;
    session
        .register_callback_init_incoming(Box::new(callback_init_incoming))
        .await;
    session
        .register_callback_init_await(Box::new(callback_init_await))
        .await;
    session
        .register_callback_init_accepted(Box::new(callback_init_accepted))
        .await;
    session
        .register_callback_init_declined(Box::new(callback_init_declined))
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
    session
        .register_callback_session_close(Box::new(callback_session_close))
        .await;

    let tx = session.get_tx().await;
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let c = tokio::signal::ctrl_c().await;
        if c.is_ok() {
            terminate(tx_clone).await;
        }
    });

    launch_terminal_program(cert.clone(), session.get_tx().await, session.clone()).await;

    tokio::time::sleep(Duration::from_millis(400)).await;
    match session.serve().await {
        Ok(_) => {}
        Err(e) => match e {
            MessagingError::ZenohError => {
                terminate(tx).await;
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
    }
}
