#![allow(dead_code)]
mod session;

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
use zenoh::prelude::r#async::*;
use zenoh::Config;

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
    format_chat_msg, format_chat_msg_fmt, short_fingerprint, PrintChatCommand, PrintCommand,
    WindowCommand, WindowManager, WindowPipe, ChatClosedCommand
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
static PIPE: OnceCell<WindowPipe<WindowCommand>> = OnceCell::const_new();

async fn println_message(window: usize, message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::Println(PrintCommand { window, message }))
        .await;
}
async fn println_chat_closed_message(message: String) {
    PIPE.get()
        .unwrap()
        .send(WindowCommand::ChatClosed(ChatClosedCommand { message }))
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
        .send(WindowCommand::Print(PrintCommand { window, message }))
        .await;
}
async fn read_message(
    window: usize,
    prompt: &str,
    upper_prompt: &str,
    timeout: i32,
) -> Result<String, ()> {
    Ok("".to_string())
}

async fn send_chat_message(window: usize, message: Option<String>) {
    unsafe {
        //PIPE.get().unwrap().tx_chat_input(message).await;
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
    async fn read_yes_or_no(
        window: usize,
        prompt: &str,
        rx: &mut mpsc::Receiver<Option<String>>,
    ) -> Result<bool, ()> {
        println_message_str(1, prompt).await;
        let input = rx.recv().await;
        if input.is_some() {
            let input = input.unwrap();
            if input.is_some() {
                let input = input.unwrap();
                if input.to_lowercase().starts_with('y') {
                    return Ok(true);
                }
            }
        }
        Ok(true)
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
            let (chat_id, chat_view) = format_chat_msg(&message, &pub_encro);
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

            println_chat_closed_message(
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
    let pipe;
    unsafe {
        pipe = PIPE.get().unwrap().clone();
    }
    let topic = Topic::Internal.as_str();
    let msg = SessionMessage::new_internal(
        "internal".to_owned(),
        "terminate".to_owned(),
        topic.to_string(),
    );
    pipe.send(WindowCommand::Shutdown()).await;
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
}

async fn launch_terminal_program(
    cert: Arc<Cert>,
    session_tx: mpsc::Sender<(String, String)>,
    mut session: Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>,
) {
    let pipe;
    unsafe {
        pipe = PIPE.get().unwrap().clone();
    }
    let (tx, mut rx) = mpsc::channel::<Option<String>>(100);
    // Setup window manager serving
    tokio::spawn(async move {
        let mut window_manager = WindowManager::new();

        let pipe_clone = pipe.clone();
        window_manager.serve(pipe_clone, tx).await;
    });
    let pipe;
    unsafe {
        pipe = PIPE.get().unwrap().clone();
    }
    // Initialize
    pipe.send(WindowCommand::Init()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let zc = session.middleware_config.clone();
    let zenoh_config = Config::from_file(zc).unwrap();
    let zenoh_session = Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
    let zenoh_handler = ZenohHandler::new(zenoh_session);

    let pgp_handler = PGPEnDeCrypt::new_no_certpass(cert.clone());

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
                    terminate(session.get_tx().await).await;
                    keep_running = false;
                    continue;
                }
                let input = input.unwrap();
                let mut s = ">> ".to_string();
                s.push_str(&input);
                println_message(1, s).await;
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
                        InputCommand::print_help().await;
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
                                            let msg = SessionMessage::new_chat(input.clone());
                                            let _ = session
                                                .session_send_msg(
                                                    &id,
                                                    msg,
                                                    &topic_out,
                                                    &zenoh_handler,
                                                )
                                                .await;
                                            let fingerprint = session.get_fingerprint().await;
                                            let userid = session.get_userid().await;

                                            let (chat_id, chat_view) =
                                                format_chat_msg_fmt(&input, &userid, &fingerprint);

                                            println_chat_message(chat_id, chat_view).await;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                keep_running = false;
            }
        }
    }
}

async fn initialize_global_value() {
    // Directly initialize the GLOBAL_VALUE using `init`
    PIPE.set(WindowPipe::new());
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

    //tokio::spawn(async move {

    //});

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

    launch_terminal_program(cert.clone(), session.get_tx().await, session.clone()).await;
}
