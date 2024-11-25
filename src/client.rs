#![allow(dead_code)]
mod session;

use crate::session::messages::MessageData::{Chat, Encrypted};
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
use tokio::sync::{mpsc, Mutex, OnceCell};
use tokio::time::{timeout, Duration};

use crate::session::middleware::ZenohHandler;
use zenoh::Config;

mod util;
use util::{get_current_datetime, short_fingerprint};

mod pgp;
use pgp::pgp::{generate_new_key_with, read_from_gpg, read_from_vec};

extern crate sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;

use clap::Parser;
use ncurses::*;

mod terminal;
use terminal::{
    format_chat_msg, format_chat_msg_fmt, AppCurrentState, ChatClosedCommand, PrintChatCommand,
    PrintCommand, SetAppStateCommand, SetChatMessagesCommand, TextStyle, WindowCommand,
    WindowManager, WindowPipe,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[clap(short, long)]
    #[arg(default_value = "new")]
    gpgkey: String,

    #[clap(long)]
    #[arg(default_value = "false")]
    test_receiver: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    test_sender: bool,

    #[clap(long)]
    #[arg(default_value = "false")]
    no_memory: bool,

    #[clap(short, long)]
    #[arg(default_value = "zenoh/config.json5")]
    zenoh_config: String,

    #[clap(short, long)]
    #[arg(default_value = "chatpgp@example.com")]
    email: String,
}

// Create a global instance of WindowManager
static PIPE: OnceCell<WindowPipe<WindowCommand>> = OnceCell::const_new();

async fn println_message(window: usize, message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::Println(PrintCommand {
            window,
            message,
            style: TextStyle::Normal,
        }))
        .await;
}
async fn println_message_style(window: usize, message: String, style: TextStyle) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::Println(PrintCommand {
            window,
            message,
            style,
        }))
        .await;
}
async fn println_chat_closed_message(message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::ChatClosed(ChatClosedCommand { message }))
        .await;
}
async fn chat_reset_messages() {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::SetChatMessages(SetChatMessagesCommand {
            chat_messages: Vec::new(),
        }))
        .await;
}
async fn set_app_state(state: AppCurrentState) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::SetAppState(SetAppStateCommand {
            state: AppCurrentState::Commands,
        }))
        .await;
}
async fn println_chat_message(chatid: String, message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::PrintChat(PrintChatCommand {
            chatid,
            message,
        }))
        .await;
}
async fn print_message(window: usize, message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::Print(PrintCommand {
            window,
            message,
            style: TextStyle::Normal,
        }))
        .await;
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
struct RemindCommand {}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct InitializeCommand {
    pub entry: usize,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct RewindCommand {
    pub entry: usize,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ForgetCommand {
    pub entry: usize,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
struct EmailCommand {
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
    Remind(RemindCommand),
    Rewind(RewindCommand),
    Forget(ForgetCommand),
    Email(EmailCommand),
}

impl InputCommand {
    fn parse_from(input: &str) -> Option<Self> {
        let binding = input.to_lowercase();
        let mut parts = binding.split_whitespace();
        match parts.next() {
            Some("list") => {
                let cmd = ListCommand {};
                Some(InputCommand::List(cmd))
            }
            Some("init") => {
                let entry = match parts.next() {
                    Some(entry) => entry.parse::<usize>().unwrap(),
                    None => 0,
                };
                let cmd = InitializeCommand { entry };
                Some(InputCommand::Initialize(cmd))
            }
            Some("exit") => {
                let cmd = ExitCommand {};
                Some(InputCommand::Exit(cmd))
            }
            Some("help") => {
                let cmd = HelpCommand {};
                Some(InputCommand::Help(cmd))
            }
            Some("remind") => {
                let cmd = RemindCommand {};
                Some(InputCommand::Remind(cmd))
            }
            Some("rewind") => {
                let entry = match parts.next() {
                    Some(entry) => entry.parse::<usize>().unwrap(),
                    None => 0,
                };
                let cmd = RewindCommand { entry };
                Some(InputCommand::Rewind(cmd))
            }
            Some("forget") => {
                let entry = match parts.next() {
                    Some(entry) => entry.parse::<usize>().unwrap(),
                    None => 0,
                };
                let cmd = ForgetCommand { entry };
                Some(InputCommand::Forget(cmd))
            }
            Some("email") => {
                let entry = match parts.next() {
                    Some(entry) => entry.parse::<usize>().unwrap(),
                    None => 0,
                };
                let cmd = EmailCommand { entry };
                Some(InputCommand::Email(cmd))
            }
            _ => None,
        }
    }

    async fn print_help(nbr_emails: u64) {
        let _help_text = String::new();
        println_message_str(1, "Available commands :) :").await;
        println_message_str(1, "  list").await;
        println_message_str(1, "  - List and enumerate all discovered peers.").await;
        println_message_str(1, "  init [entry]").await;
        println_message_str(1, "  - Initialize a chat session with a peer").await;
        println_message_str(1, "    enumerated as per 'list'").await;
        println_message_str(1, "  remind").await;
        println_message_str(1, "  - List and enumerate encrypted and stored sessions.").await;
        println_message_str(1, "  rewind [entry]").await;
        println_message_str(1, "  - Decrypts and displays previous chat sessions").await;
        println_message_str(1, "    enumerated as per 'remind'.").await;
        println_message_str(1, "  forget [entry]").await;
        println_message_str(1, "  - Delete the record of a previous chat session").await;
        println_message_str(1, "    enumerated as per 'remind'.").await;
        println_message_str(1, "  email [entry]").await;
        println_message_str(
            1,
            &format!(" There has been {} emails received since start", nbr_emails),
        )
        .await;
        println_message_str(
            1,
            "  - Send an email to someone encrypted as per a previous session",
        )
        .await;
        println_message_str(1, "    enumerated as per 'remind'.").await;
        println_message_str(1, "  exit").await;
        println_message_str(1, "  - Exit the program.").await;
    }
    async fn print_small_help() {
        println_message(1, InputCommand::get_small_help()).await;
    }
    fn get_small_help() -> String {
        "Welcome to Chat-PGP. Type 'help' for help.".to_string()
    }
    async fn read_yes_or_no(
        window: usize,
        prompt: &str,
        rx: &mut mpsc::Receiver<Option<WindowCommand>>,
    ) -> Result<bool, ()> {
        println_message_str(1, prompt).await;
        let input = rx.recv().await;
        if input.is_some() {
            let input = input.unwrap();
            if input.is_some() {
                let input = input.unwrap();
                let input = match input {
                    WindowCommand::Println(input) => input.message,
                    _ => "".into(),
                };
                if input.to_lowercase().starts_with('y') {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    async fn read_incoming(
        prompt: &str,
        rx: &mut mpsc::Receiver<Option<WindowCommand>>,
    ) -> Result<String, ()> {
        println_message_style(1, prompt.to_string(), TextStyle::Bold).await;
        let input = rx.recv().await;
        if input.is_some() {
            let input = input.unwrap();
            if input.is_some() {
                let input = input.unwrap();
                let input = match input {
                    WindowCommand::Println(input) => input.message,
                    _ => "".into(),
                };
                return Ok(input);
            }
        }
        Err(())
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
            let (mut chat_id, chat_view) = format_chat_msg(&message, &pub_encro);
            let fingerprint = short_fingerprint(&pub_encro.get_public_key_fingerprint());
            chat_id.push_str(" ");
            chat_id.push_str(&fingerprint);
            println_chat_message(chat_id, chat_view).await;
        }
        _ => {}
    }
}

async fn cb_chat_input(
    pub_key: String,
    session_id: String,
    topic_out: String,
    input: String,
) -> Option<(String, String)> {
    let pub_key_decoded = match base64::decode(pub_key) {
        Err(_) => {
            return None;
        }
        Ok(pub_key) => pub_key,
    };
    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
        Ok(pub_encro) => {
            let fingerprint = pub_encro.get_public_key_fingerprint();
        }
        _ => {}
    }

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

            println_chat_closed_message(format!(
                "[{} - {} ({}) has terminated the chat session]",
                date_and_time, userid, fingerprint_short
            ))
            .await;

            set_app_state(AppCurrentState::Commands).await;
            chat_reset_messages().await;
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

async fn cb_terminate() {}

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
    let pipe = PIPE.get().unwrap().clone();
    let topic = Topic::Internal.as_str();
    let msg = SessionMessage::new_internal(
        "internal".to_owned(),
        "terminate".to_owned(),
        topic.to_string(),
    );
    pipe.send(WindowCommand::Shutdown()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = session_tx
        .send((topic.to_string(), msg.serialize().unwrap()))
        .await;
}

async fn terminal_program(
    session_tx: mpsc::Sender<(String, String)>,
    cert: Arc<Cert>,
    session: Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>,
) {
}

async fn launch_terminal_program(
    cert: Arc<Cert>,
    session_tx: mpsc::Sender<(String, String)>,
    mut session: Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>,
) -> Result<(), ()> {
    let pipe = PIPE.get().unwrap().clone();
    let zc = session.middleware_config.clone();
    let zenoh_config = Config::from_file(zc.clone()).unwrap();
    let zenoh_session;
    {
        let zenoh_connection = zenoh::open(zenoh_config).await;
        if zenoh_connection.is_err() {
            terminate(session.get_tx().await).await;
            return Err(());
        }
        let zenoh_connection = zenoh_connection.unwrap();
        zenoh_session = Arc::new(Mutex::new(zenoh_connection));
    }
    let zenoh_handler = ZenohHandler::new(zenoh_session.clone());

    let (tx, mut rx) = mpsc::channel::<Option<WindowCommand>>(100);
    // Setup window manager serving
    tokio::spawn(async move {
        let mut window_manager = WindowManager::new();

        let pipe_clone = pipe.clone();
        window_manager.serve(pipe_clone, tx).await;
    });
    let pipe = PIPE.get().unwrap().clone();
    // Initialize
    pipe.send(WindowCommand::Init()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Launch window manager program
    tokio::time::sleep(Duration::from_millis(400)).await;
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
                        let r = InputCommand::read_yes_or_no(1, ">> ", &mut rx).await;
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
                        } else {
                            println_message_str(1, "-- Declined this chat request.").await;
                            let _ = session.decline_pending_request(&session_id).await;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            let timeout_duration = Duration::from_secs(1);
            let input = timeout(timeout_duration, rx.recv()).await;
            if input.is_err() {
                continue;
            }
            let input = input.unwrap();
            if input.is_some() {
                let input = input.unwrap();
                if input.is_none() {
                    // terminate
                    //
                    let topic = Topic::Internal.as_str();
                    let msg = SessionMessage::new_internal(
                        "internal".to_owned(),
                        "terminate".to_owned(),
                        topic.to_string(),
                    );

                    let _ = session_tx
                        .send((topic.to_string(), msg.serialize().unwrap()))
                        .await;

                    keep_running = false;

                    terminate(session_tx.clone()).await;
                    continue;
                }
                let input = input.unwrap();
                match input {
                    WindowCommand::ChatClosed(_) => {
                        let session_ids = session.get_session_ids().await;
                        let zenoh_handler =
                            Arc::new(Mutex::new(ZenohHandler::new(zenoh_session.clone())));
                        for session_id in session_ids {
                            session
                                .terminate_session(&session_id, zenoh_handler.clone())
                                .await;
                        }
                    }
                    _ => {}
                };

                let mut s = ">> ".to_string();
                let input = match input {
                    WindowCommand::Println(input) => input.message,
                    _ => "".into(),
                };
                if session.get_number_of_sessions().await == 0 {
                    s.push_str(&input);
                    println_message(1, s).await;
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
                                "-- Did not discover any other peers out there ¯\\_(ツ)_/¯...",
                            )
                            .await;
                        } else {
                            println_message_str(1, "Peers detected:").await;
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
                            let response = InputCommand::read_yes_or_no(1, ">> ", &mut rx).await;
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
                        InputCommand::print_help(session.get_nbr_emails().await).await;
                    }
                    Some(InputCommand::Remind(_)) => {
                        let ids = session.get_reminded_session_ids().await;
                        if ids.len() == 0 {
                            println_message_str(
                                1,
                                "There is no memory of any previous sessions ¯\\_(ツ)_/¯... ",
                            )
                            .await;
                        } else {
                            for (i, id) in ids.iter().enumerate() {
                                let len =
                                    session.get_reminded_length(id).await.unwrap_or_else(|_| 0);
                                let mut peers = "".to_string();
                                let last_active = session
                                    .get_reminded_last_active(id)
                                    .await
                                    .unwrap_or_else(|_| "".to_string());
                                let others = session
                                    .get_reminded_others(id)
                                    .await
                                    .unwrap_or_else(|_| Vec::new());
                                for other in others.iter() {
                                    if peers.len() > 0 {
                                        peers.push_str(", ");
                                    }
                                    let pub_key_decoded = match base64::decode(other) {
                                        Err(_) => Err(()),
                                        Ok(pub_key) => Ok(pub_key),
                                    };
                                    if pub_key_decoded.is_ok() {
                                        let pub_key_decoded = pub_key_decoded.unwrap();
                                        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
                                            Ok(pub_encro) => {
                                                peers.push_str(&format!(
                                                    "{} ({})",
                                                    pub_encro.get_userid(),
                                                    short_fingerprint(
                                                        &pub_encro.get_public_key_fingerprint()
                                                    )
                                                ));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                println_message_str(
                                    1,
                                    &format!(
                                        "{}: {}, (last active: {}, messages: {})",
                                        i + 1,
                                        peers,
                                        last_active,
                                        len
                                    ),
                                )
                                .await;
                            }
                        }
                    }
                    Some(InputCommand::Rewind(cmd)) => {
                        let entry = cmd.entry;
                        let ids = session.get_reminded_session_ids().await;
                        if ids.len() == 0 || entry > ids.len() || entry <= 0 {
                            println_message_str(
                                1,
                                "There is no memory of that session ¯\\_(ツ)_/¯... {} ",
                            )
                            .await;
                        } else {
                            let session_log =
                                session.get_reminded_session_log(&ids[entry - 1]).await;
                            if session_log.is_err() {
                                println_message_str(1, "Sorry. This did not work ¯\\_(ツ)_/¯... ")
                                    .await;
                            } else {
                                let (encrypted_sym_key, logs) = session_log.unwrap();
                                println_message_str(
                                    1,
                                    "Decrypting stored encrypted session key...",
                                )
                                .await;
                                let sym_key =
                                    session.decrypt_encrypted_str(encrypted_sym_key).await;

                                if sym_key.is_ok() {
                                    println_message_str(1, "Restored session key.").await;
                                    println_message_str(1, "Decrypting memory.").await;
                                    let sym_key = sym_key.unwrap();
                                    for logmsg in logs {
                                        let msg = logmsg.message;
                                        let read = logmsg.read;
                                        match msg.message {
                                            Encrypted(msg) => {
                                                let hidden_msg = session
                                                    .decrypt_sym_encrypted_msg(
                                                        sym_key.clone(),
                                                        msg.data.clone(),
                                                    )
                                                    .await;
                                                if hidden_msg.is_ok() {
                                                    let msg = hidden_msg.unwrap();
                                                    match msg.message {
                                                        Chat(msg) => {
                                                            if read {
                                                                println_message_style(
                                                                    1,
                                                                    format!(
                                                                        "[{}] {} ({}) - {}",
                                                                        msg.date_time,
                                                                        msg.sender_userid,
                                                                        short_fingerprint(
                                                                            &msg.sender_fingerprint
                                                                        ),
                                                                        msg.message
                                                                    ),
                                                                    TextStyle::Bold,
                                                                )
                                                                .await;
                                                            } else {
                                                                println_message(
                                                                    1,
                                                                    format!(
                                                                        "[{}] {} ({})- {}",
                                                                        msg.date_time,
                                                                        msg.sender_userid,
                                                                        short_fingerprint(
                                                                            &msg.sender_fingerprint
                                                                        ),
                                                                        msg.message
                                                                    ),
                                                                )
                                                                .await;
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                } else {
                                    println_message_str(1, "Sorry. Cannot read that memory.. Perhaps you were using a different PGP key?")
                                    .await;
                                }
                            }
                        }
                    }
                    Some(InputCommand::Forget(cmd)) => {
                        let entry = cmd.entry;
                        let ids = session.get_reminded_session_ids().await;
                        if ids.len() == 0 || entry > ids.len() || entry <= 0 {
                            println_message_str(
                                1,
                                "There is no memory of that session ¯\\_(ツ)_/¯...",
                            )
                            .await;
                        } else {
                            let id = &ids[entry - 1];
                            let last_active = session.get_reminded_last_active(id).await;
                            if last_active.is_ok() {
                                println_message_str(1,
                                    &format!("-- Are you sure you want to delete this session memory from {}? [y/n]",
                                    last_active.unwrap()),
                                )
                                .await;
                            }
                            let r = InputCommand::read_yes_or_no(1, ">> ", &mut rx).await;
                            if r.is_ok() && r.unwrap() {
                                let _ = session.remove_memory_entry(&ids[entry - 1]).await;
                                println_message_str(1, "The memory has been removed!").await;
                            }
                        }
                    }
                    Some(InputCommand::Email(cmd)) => {
                        let entry = cmd.entry;
                        let ids = session.get_reminded_session_ids().await;
                        if ids.len() == 0 || entry > ids.len() || entry <= 0 {
                            println_message_str(
                                1,
                                "There is no memory of that session ¯\\_(ツ)_/¯...",
                            )
                            .await;
                        } else {
                            let session_id = &ids[entry - 1];
                            let content =
                                InputCommand::read_incoming("Write email content", &mut rx).await;
                            if content.is_ok() {
                                let content = content.unwrap();
                                println_message_str(1, "Sending message...").await;
                                let res = session
                                    .send_email(session_id, content, &zenoh_handler)
                                    .await;
                                if res.is_err() {
                                    println_message_style(
                                        1,
                                        "Failed to send the email".to_string(),
                                        TextStyle::Bold,
                                    )
                                    .await;
                                } else {
                                    println_message_style(
                                        1,
                                        "Email sent".to_string(),
                                        TextStyle::Bold,
                                    )
                                    .await;
                                }
                            } else {
                                println_message_str(1, "Failed to send that email ¯\\_(ツ)_/¯...")
                                    .await;
                            }
                        }
                    }
                    None => {
                        // Send this input to listeners
                        if input.len() > 0 && session.get_number_of_sessions().await > 0 {
                            // FOR NOW: Only one session to send at a time...
                            let id = session.get_session_ids().await[0].clone();
                            let other_pub_key = session.get_pub_key_from_session_id(&id).await;
                            if other_pub_key.is_ok() {
                                let other_pub_key = other_pub_key.unwrap();
                                let pub_key_decoded = match base64::decode(other_pub_key) {
                                    Err(_) => Err(()),
                                    Ok(pub_key) => Ok(pub_key),
                                };
                                if pub_key_decoded.is_ok() {
                                    let pub_key_decoded = pub_key_decoded.unwrap();
                                    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
                                        Ok(pub_encro) => {
                                            let fingerprint =
                                                pub_encro.get_public_key_fingerprint();
                                            let topic_out = Topic::messaging_topic_in(&fingerprint);
                                            let fingerprint = session.get_fingerprint().await;
                                            let userid = session.get_userid().await;

                                            let msg = SessionMessage::new_chat(
                                                input.clone(),
                                                userid.clone(),
                                                fingerprint.clone(),
                                            );
                                            let _ = session
                                                .session_send_msg(
                                                    &id,
                                                    msg,
                                                    &topic_out,
                                                    &zenoh_handler,
                                                )
                                                .await;

                                            let (_, chat_view) =
                                                format_chat_msg_fmt(&input, &userid, &fingerprint);
                                            let mut chat_id = pub_encro.get_userid();
                                            let fingerprint = short_fingerprint(
                                                &pub_encro.get_public_key_fingerprint(),
                                            );
                                            chat_id.push_str(" ");
                                            chat_id.push_str(&fingerprint);
                                            println_chat_message(chat_id, chat_view).await;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        } else {
                            InputCommand::print_help(session.get_nbr_emails().await).await;
                        }
                    }
                }
            } else {
                keep_running = false;
            }
        }
    }
    Ok(())
}

async fn initialize_global_value() {
    // Directly initialize the GLOBAL_VALUE using `init`
    let _ = PIPE.set(WindowPipe::new());
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let gpgkey = cli.gpgkey;
    let test_sender = cli.test_sender;
    let test_receiver = cli.test_receiver;
    let zenoh_config = cli.zenoh_config;
    let memory = !cli.no_memory;
    let email = cli.email;

    let mut cert = None;

    // check if gpgkey == "new"
    if gpgkey == "new" {
        cert = Some(generate_new_key_with(email).unwrap());
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
    let mut session = Session::new(pgp_handler, zenoh_config.clone(), false, memory);

    if test_receiver {
        session.set_discovery_interval_seconds(1);
        let mut session_clone = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3000)).await;
            session_clone.stop_session().await;
        });
        let _ = session.serve().await;
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

        let _ = session.serve().await;
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
    let callback_chat_input = move |arg1: String, arg2: String, arg3: String, arg4: String| {
        Box::pin(cb_chat_input(arg1, arg2, arg3, arg4))
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

    // First task to initialize the global value
    let initializer = tokio::spawn(async {
        initialize_global_value().await;
    });

    // Wait for the initializer to complete
    initializer.await.unwrap();

    let tx = session.get_tx().await;
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let c = tokio::signal::ctrl_c().await;
        if c.is_ok() {
            terminate(tx_clone).await;
        }
    });

    let mut session_clone = session.clone();
    tokio::spawn(async move {
        let _ = match session_clone.serve().await {
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
        };
    });

    let _ = launch_terminal_program(cert.clone(), session.get_tx().await, session.clone()).await;
}
