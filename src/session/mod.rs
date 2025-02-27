use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout, Duration};

pub mod crypto;
pub mod inbox;
pub mod memory;
pub mod messages;
pub mod middleware;
pub mod protocol;

use crate::pgp::pgp::read_from_vec;
use crate::util::{get_current_datetime, RingBuffer};
use async_recursion::async_recursion;
use crypto::{
    sha256sum, ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalDecrypt, CrypticalEncrypt,
    CrypticalID, CrypticalSign, CrypticalVerify, PGPEnCryptOwned, PGPEnDeCrypt,
};
use futures::prelude::*;
use inbox::Inbox;
use inbox::InboxEntry;
use memory::{Memory, SessionLogMessage};
use messages::MessageData::{
    Chat, Close, Discovery, DiscoveryReply, Email, Encrypted, EncryptedRelay, Heartbeat, Init,
    InitAwait, InitDecline, InitOk, Internal, Ping, Replay, ReplayResponse,
};
use messages::MessagingError::*;
use messages::SessionMessage as Message;
use messages::{
    ChatMsg, DiscoveryMsg, DiscoveryReplyMsg, EmailMsg, EncryptedMsg, EncryptedRelayMsg, InitMsg,
    InitOkMsg, InternalMsg, MessageData, MessageListener, MessagebleTopicAsync,
    MessagebleTopicAsyncPublishReads, MessagebleTopicAsyncReadTimeout, MessagingError,
    SessionErrorCodes, SessionErrorMsg,
};
use middleware::ZenohHandler;
use protocol::*;
use zenoh::Config;

#[derive(PartialEq, Clone)]
pub enum SessionState {
    Initializing,
    Active,
    Authorizing,
    Inactive,
    Closed,
}

pub enum SessionError {
    SessionError(SessionErrorMsg),
}

#[derive(Clone)]
pub struct SessionData<SessionCrypto>
where
    SessionCrypto: CrypticalEncrypt + CrypticalDecrypt,
{
    pub id: String,
    pub last_active: SystemTime,
    pub state: SessionState,
    pub pub_key: String,
    pub messages: Vec<Message>,
    pub sym_encro: SessionCrypto,
    pub sym_key_encrypted_host: String,
}

pub struct Session<SessionCrypto, HostCrypto>
where
    SessionCrypto: CrypticalEncrypt + CrypticalDecrypt,
    HostCrypto: CrypticalEncrypt + CrypticalDecrypt,
{
    pub sessions: Arc<Mutex<HashMap<String, SessionData<SessionCrypto>>>>,
    pub discovered: Arc<Mutex<HashMap<String, String>>>,
    pub requests_outgoing_initialization: Arc<Mutex<Vec<(String, String)>>>,
    pub requests_incoming_initialization:
        Arc<Mutex<Vec<(SessionData<SessionCrypto>, Message, String)>>>,
    pub host_encro: Arc<Mutex<HostCrypto>>,
    pub tx: mpsc::Sender<(String, String)>,
    pub tx_chat: mpsc::Sender<(String, String)>,
    pub rx_chat: Arc<Mutex<mpsc::Receiver<(String, String)>>>,
    pub rx: Arc<Mutex<mpsc::Receiver<(String, String)>>>,
    pub callbacks_chat: Arc<
        Mutex<
            Vec<
                Box<
                    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>>
                        + Send
                        + Sync,
                >,
            >,
        >,
    >,

    pub callbacks_discovered: Arc<
        Mutex<Vec<Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>>>,
    >,
    pub callbacks_init_incoming: Arc<
        Mutex<Vec<Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>>>,
    >,
    pub callbacks_init_await: Arc<
        Mutex<Vec<Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>>,
    >,
    pub callbacks_init_accepted: Arc<
        Mutex<Vec<Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>>,
    >,
    pub callbacks_session_closed: Arc<
        Mutex<
            Vec<
                Box<
                    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>>
                        + Send
                        + Sync,
                >,
            >,
        >,
    >,
    pub callbacks_init_declined: Arc<
        Mutex<
            Vec<
                Box<
                    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>>
                        + Send
                        + Sync,
                >,
            >,
        >,
    >,
    pub callbacks_terminate:
        Arc<Mutex<Vec<Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>>>,
    pub callbacks_chat_input: Arc<
        Mutex<
            Vec<
                Box<
                    dyn Fn(
                            String,
                            String,
                            String,
                            String,
                        )
                            -> Pin<Box<dyn Future<Output = Option<(String, String)>> + Send>>
                        + Send
                        + Sync,
                >,
            >,
        >,
    >,

    pub middleware_config: String,
    discovery_interval_seconds: u64,
    heartbeat_interval_seconds: u64,
    added_emails: Arc<Mutex<u64>>,
    relay: bool,
    memory: Arc<Mutex<Memory>>,
    memory_active: bool,
    inbox: Arc<Mutex<Inbox>>,
    running: Arc<Mutex<bool>>,
}

impl Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt> {
    pub fn new(
        host_encro: PGPEnDeCrypt,
        middleware_config: String,
        relay: bool,
        memory_active: bool,
    ) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let (tx_chat, rx_chat) = mpsc::channel(100);
        let fingerprint = host_encro.get_public_key_fingerprint();
        let memory_file = &format!(".memory_{}", fingerprint);
        let inbox_file = &format!(".inbox_{}", fingerprint);
        if relay {
            println!("relay session");
        }
        Session {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            discovered: Arc::new(Mutex::new(HashMap::new())),
            requests_incoming_initialization: Arc::new(Mutex::new(Vec::new())),
            requests_outgoing_initialization: Arc::new(Mutex::new(Vec::new())),

            host_encro: Arc::new(Mutex::new(host_encro)),
            tx: tx.clone(),
            tx_chat: tx_chat.clone(),
            rx_chat: Arc::new(Mutex::new(rx_chat)),
            rx: Arc::new(Mutex::new(rx)),

            callbacks_chat: Arc::new(Mutex::new(Vec::new())),
            callbacks_discovered: Arc::new(Mutex::new(Vec::new())),
            callbacks_init_incoming: Arc::new(Mutex::new(Vec::new())),
            callbacks_init_await: Arc::new(Mutex::new(Vec::new())),
            callbacks_init_declined: Arc::new(Mutex::new(Vec::new())),
            callbacks_init_accepted: Arc::new(Mutex::new(Vec::new())),
            callbacks_session_closed: Arc::new(Mutex::new(Vec::new())),
            callbacks_terminate: Arc::new(Mutex::new(Vec::new())),
            callbacks_chat_input: Arc::new(Mutex::new(Vec::new())),

            middleware_config,
            discovery_interval_seconds: 10,
            heartbeat_interval_seconds: 10,
            relay: relay,
            memory: Arc::new(Mutex::new(
                Memory::from_file(memory_file).unwrap_or_else(|_| Memory::new(&memory_file)),
            )),
            memory_active,
            inbox: Arc::new(Mutex::new(
                Inbox::from_file(inbox_file).unwrap_or_else(|_| Inbox::new(&inbox_file)),
            )),
            added_emails: Arc::new(Mutex::new(0)),
            running: Arc::new(Mutex::new(true)),
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
            discovered: Arc::clone(&self.discovered),
            requests_incoming_initialization: Arc::clone(&self.requests_incoming_initialization),
            requests_outgoing_initialization: Arc::clone(&self.requests_outgoing_initialization),

            host_encro: Arc::clone(&self.host_encro),
            tx: self.tx.clone(),
            tx_chat: self.tx_chat.clone(),
            rx: self.rx.clone(),
            rx_chat: self.rx_chat.clone(),
            callbacks_chat: Arc::clone(&self.callbacks_chat),
            callbacks_discovered: Arc::clone(&self.callbacks_discovered),
            callbacks_init_incoming: Arc::clone(&self.callbacks_init_incoming),
            callbacks_init_await: Arc::clone(&self.callbacks_init_await),
            callbacks_init_declined: Arc::clone(&self.callbacks_init_declined),
            callbacks_init_accepted: Arc::clone(&self.callbacks_init_accepted),
            callbacks_session_closed: Arc::clone(&self.callbacks_session_closed),
            callbacks_terminate: Arc::clone(&self.callbacks_terminate),
            callbacks_chat_input: Arc::clone(&self.callbacks_chat_input),

            middleware_config: self.middleware_config.clone(),
            discovery_interval_seconds: self.discovery_interval_seconds,
            heartbeat_interval_seconds: self.heartbeat_interval_seconds,
            relay: self.relay,
            added_emails: self.added_emails.clone(),
            memory: self.memory.clone(),
            memory_active: self.memory_active,
            inbox: self.inbox.clone(),
            running: self.running.clone(),
        }
    }

    pub fn get_running(&self) -> Arc<Mutex<bool>> {
        self.running.clone()
    }

    pub fn set_tx_chat(&mut self, tx: mpsc::Sender<(String, String)>) {
        self.tx_chat = tx;
    }

    pub async fn get_pending_request(&self) -> Option<SessionData<ChaCha20Poly1305EnDeCrypt>> {
        let requests = self.requests_incoming_initialization.lock().await;
        if requests.len() > 0 {
            let session_data = requests[0].0.clone();
            return Some(session_data);
        }
        None
    }

    pub async fn decline_pending_request(&mut self, session_id: &str) -> Result<(), ()> {
        let mut requests = self.requests_incoming_initialization.lock().await;
        let mut index = None;

        for (i, (session_data, _, _)) in requests.iter().enumerate() {
            let id = session_data.id.clone();
            if id == session_id {
                requests.remove(i); // Remove the request while the lock is still active
                index = Some(i);
                break;
            }
        }

        if index.is_none() {
            return Err(());
        }
        Ok(())
    }

    pub async fn accept_pending_request(&mut self, session_id: &str) -> Result<(), ()> {
        let mut session_data_incoming = None;
        let mut session_init_ok_msg = None;
        let mut session_init_ok_msg_topic = None;
        {
            let mut requests = self.requests_incoming_initialization.lock().await;
            let _index;

            for (i, (session_data, message, topic)) in requests.iter().enumerate() {
                let id = session_data.id.clone();
                if id == session_id {
                    session_init_ok_msg = Some(message.clone());
                    session_data_incoming = Some(session_data.clone());
                    session_init_ok_msg_topic = Some(topic.clone());
                    _index = Some(i);
                    requests.remove(i); // Remove the request while the lock is still active
                    break;
                }
            }

            // Ensure the lock is dropped before proceeding
            if session_data_incoming.is_none() {
                return Err(());
            }
        }

        // Proceed after the lock is dropped
        let session_data = session_data_incoming.unwrap();
        let key = session_data.id.clone();
        let pub_key = session_data.pub_key.clone();
        let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
        let cert = read_from_vec(&pub_key_dec);
        if cert.is_err() {
            return Err(());
        }
        let cert = cert.unwrap();
        let _fingerprint = cert.fingerprint().to_string();

        {
            let mut hm = self.sessions.lock().await;
            hm.insert(key.clone(), session_data.clone());
        }

        if session_init_ok_msg.is_some() {
            let zc = self.middleware_config.clone();
            let zenoh_config = Config::from_file(zc).unwrap();
            let zenoh_session = Arc::new(Mutex::new(zenoh::open(zenoh_config).await.unwrap()));
            let handler = ZenohHandler::new(zenoh_session);
            let msg = session_init_ok_msg.unwrap().clone();
            let _ = self
                .send(msg, session_init_ok_msg_topic.unwrap().as_str(), &handler)
                .await;
            self.chat(key.clone(), false, pub_key).await;
        }

        Ok(())
    }

    pub fn session_recv_msg<T: MessageListener>(
        &mut self,
        listener: &T,
    ) -> Result<Message, MessagingError> {
        match listener.listen() {
            Ok(message) => Ok(message),
            Err(error_msg) => Err(error_msg),
        }
    }

    pub async fn get_tx(&self) -> mpsc::Sender<(String, String)> {
        self.tx.clone()
    }

    pub async fn encrypt_msg(
        &mut self,
        session_id: &str,
        msg: &Message,
    ) -> Result<EncryptedMsg, MessagingError> {
        let session = self.sessions.lock().await;
        let session_data = match session.get(session_id) {
            Some(sd) => sd,
            None => {
                return Err(SessionNotFound);
            }
        };
        let msg_string = match msg.serialize() {
            Ok(v) => v,
            Err(_) => {
                return Err(Serialization);
            }
        };
        let cipher = &session_data.sym_encro;
        let msg_encrypted = match cipher.encrypt(&msg_string) {
            Ok(m) => m,
            Err(_) => {
                return Err(Encryption);
            }
        };
        Ok(EncryptedMsg {
            data: msg_encrypted,
        })
    }

    pub async fn session_send_msg<T: MessagebleTopicAsync + MessagebleTopicAsyncReadTimeout>(
        &mut self,
        session_id: &str,
        msg: Message,
        topic: &str,
        gateway: &T,
    ) -> Result<(), MessagingError> {
        match self.encrypt_msg(session_id, &msg).await {
            Ok(msg) => {
                let msg_enc =
                    Message::new_from_data(session_id.to_string(), MessageData::Encrypted(msg));
                if self.memory_active && session_id.len() > 0 {
                    let _ = self
                        .memory
                        .lock()
                        .await
                        .add_entry_message(session_id, msg_enc.clone());
                }
                return self.send(msg_enc, topic, gateway).await;
            }
            Err(err) => Err(err),
        }
    }

    // Register a new callback
    pub async fn register_callback_chat(
        &self,
        callback: Box<
            dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
        >,
    ) {
        let mut callbacks = self.callbacks_chat.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_discovered(
        &self,
        callback: Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_discovered.lock().await;
        callbacks.push(callback);
    }

    pub async fn register_callback_session_close(
        &self,
        callback: Box<
            dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
        >,
    ) {
        let mut callbacks = self.callbacks_session_closed.lock().await;
        callbacks.push(callback);
    }

    pub async fn register_callback_init_incoming(
        &self,
        callback: Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_init_incoming.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_init_await(
        &self,
        callback: Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_init_await.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_init_declined(
        &self,
        callback: Box<
            dyn Fn(String, String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
        >,
    ) {
        let mut callbacks = self.callbacks_init_declined.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_init_accepted(
        &self,
        callback: Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_init_accepted.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_terminate(
        &self,
        callback: Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_terminate.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_chat_input(
        &self,
        callback: Box<
            dyn Fn(
                    String,
                    String,
                    String,
                    String,
                )
                    -> Pin<Box<dyn Future<Output = Option<(String, String)>> + Send>>
                + Send
                + Sync,
        >,
    ) {
        let mut callbacks = self.callbacks_chat_input.lock().await;
        callbacks.push(callback);
    }

    async fn call_callbacks_chat(&self, arg1: &str, arg2: &str) {
        let callbacks = self.callbacks_chat.lock().await;
        for callback in callbacks.iter() {
            callback(arg1.to_string(), arg2.to_string()).await;
        }
    }
    async fn call_callbacks_session_closed(&self, arg1: &str, arg2: &str) {
        let callbacks = self.callbacks_session_closed.lock().await;
        for callback in callbacks.iter() {
            callback(arg1.to_string(), arg2.to_string()).await;
        }
    }
    async fn call_callbacks_terminate(&self) {
        let callbacks = self.callbacks_terminate.lock().await;
        for callback in callbacks.iter() {
            callback().await;
        }
    }
    async fn call_callbacks_init_incoming(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_init_incoming.lock().await;
        for callback in callbacks.iter() {
            if !callback(arg1.to_string()).await {
                return false;
            }
        }
        true
    }
    async fn call_callbacks_init_await(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_init_await.lock().await;
        for callback in callbacks.iter() {
            callback(arg1.to_string()).await;
        }
        true
    }
    async fn call_callbacks_init_accepted(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_init_accepted.lock().await;
        for callback in callbacks.iter() {
            callback(arg1.to_string()).await;
        }
        true
    }
    async fn call_callbacks_init_declined(&self, arg1: &str, arg2: &str) -> bool {
        let callbacks = self.callbacks_init_declined.lock().await;
        for callback in callbacks.iter() {
            callback(arg1.to_string(), arg2.to_string()).await;
        }
        true
    }
    async fn call_callbacks_discovered(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_discovered.lock().await;
        for callback in callbacks.iter() {
            if !callback(arg1.to_string()).await {
                return false;
            }
        }
        true
    }

    pub async fn inbox_get_sender_session_ids(&self, sender: String) -> Result<Vec<String>, ()> {
        self.inbox.lock().await.get_sender_session_ids(sender)
    }

    pub async fn inbox_mark_as_read(&mut self, id: &str) -> bool {
        self.inbox.lock().await.mark_as_read(id)
    }

    pub async fn inbox_get_senders(&self) -> Vec<String> {
        self.inbox.lock().await.get_senders()
    }

    pub async fn inbox_get_entries(&self) -> Vec<InboxEntry> {
        self.inbox.lock().await.get_entries()
    }

    pub async fn inbox_get_entry(&self, entry: usize) -> Result<InboxEntry, ()> {
        self.inbox.lock().await.get_entry(entry)
    }

    pub async fn initialize_session_zenoh(
        &mut self,
        pub_key: String,
        zenoh_handler: &ZenohHandler,
    ) -> Result<String, String> {
        let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
        let cert = read_from_vec(&pub_key_dec);
        if cert.is_err() {
            return Err("Failed to parse public key".to_owned());
        }
        let cert = cert.unwrap();
        let other_key_fingerprint = cert.fingerprint().to_string();
        let pub_key = self.host_encro.lock().await.get_public_key_fingerprint();
        let signature = match self.host_encro.lock().await.sign(&pub_key) {
            Ok(s) => s,
            Err(e) => {
                return Err(e);
            }
        };

        let pub_key = self.host_encro.lock().await.get_public_key_as_base64();
        let mut challenge = String::new();
        let message = Message::new_init(pub_key, signature, &mut challenge);
        let mut topic = Topic::Initialize.as_str().to_string();
        topic.push_str("/");
        topic.push_str(&cert.fingerprint().to_string());
        let _await_response_interval = Duration::from_secs(60);

        {
            let mut requests = self.requests_outgoing_initialization.lock().await;
            requests.push((other_key_fingerprint.clone(), challenge));
        }

        let _ = zenoh_handler.send_message(&topic, message).await;
        Ok("".to_string())
    }

    pub async fn serve_topics(
        &mut self,
        topics: Vec<String>,
        tx: &mpsc::Sender<(String, String)>,
        blocking: bool,
    ) {
        let mut handles = Vec::new();

        for topic in topics {
            let tx_clone = tx.clone();
            let _t = topic.clone();

            let terminate_callbacks = self.callbacks_terminate.clone();
            let running = self.running.clone();

            let zc = self.middleware_config.clone();
            sleep(Duration::from_millis(100)).await;
            let h = tokio::spawn(async move {
                let zenoh_config = Config::from_file(zc).unwrap();
                let zenoh_session = zenoh::open(zenoh_config).await;

                if zenoh_session.is_err() {
                    let callbacks = terminate_callbacks.lock().await;
                    for callback in callbacks.iter() {
                        callback().await;
                    }
                    return false;
                }
                let zenoh_session = Arc::new(Mutex::new(zenoh_session.unwrap()));
                let handler = ZenohHandler::new(zenoh_session);
                let mut keep_running = *running.lock().await;
                while keep_running {
                    let _result = handler.read_messages(&topic, &tx_clone).await;
                    {
                        keep_running = *running.lock().await;
                    }
                }
                true
            });

            handles.push(h);
        }

        if blocking {
            for h in handles {
                h.await.unwrap();
            }
        }
    }

    pub async fn chat(&mut self, session_id: String, blocking: bool, other_key: String) {
        let pub_key_fingerprint = self.host_encro.lock().await.get_public_key_fingerprint();
        let topic_in = Topic::messaging_topic_in(pub_key_fingerprint.as_ref());

        let mut topics: Vec<String> = Vec::new();
        topics.push(topic_in);

        let tx_clone = self.tx_chat.clone();
        self.serve_topics(topics, &tx_clone, false).await;

        let callbacks = self.callbacks_chat.clone();
        let running = self.running.clone();
        let rx_chat = self.rx_chat.clone();
        let rx_session = self.clone();
        let memory = self.memory.clone();
        let memory_active = self.memory_active;
        let h = tokio::spawn(async move {
            let mut keep_running = *running.lock().await;
            while keep_running {
                let input = rx_chat.lock().await.recv().await;
                if input.is_some() {
                    let (_, msg) = input.unwrap();
                    let mut message_received: Option<String> = None;
                    match Message::deserialize(&msg) {
                        Ok(message) => match message.clone().message {
                            Encrypted(msg) => {
                                match rx_session
                                    .decrypt_encrypted_msg(session_id.clone(), msg)
                                    .await
                                {
                                    Ok(msg) => match msg.message {
                                        Chat(msg) => {
                                            message_received = Some(msg.message);
                                            {
                                                if memory_active {
                                                    let _ = memory.lock().await.add_entry_message(
                                                        &session_id.clone(),
                                                        message.clone(),
                                                    );
                                                }
                                            }
                                        }
                                        _ => {}
                                    },
                                    Err(_) => {}
                                }
                            }
                            _ => {}
                        },
                        Err(_) => {}
                    }
                    if message_received.is_some() {
                        let message_received = message_received.unwrap();
                        let callbacks = callbacks.lock().await;
                        for callback in callbacks.iter() {
                            callback(other_key.clone(), message_received.clone()).await
                        }
                    }
                }
                {
                    keep_running = *running.lock().await;
                }
            }
        });

        if blocking {
            h.await.unwrap();
        }
    }

    pub async fn get_sessions(&self) -> HashMap<String, SessionData<ChaCha20Poly1305EnDeCrypt>> {
        let hm = self.sessions.lock().await;
        hm.clone()
    }

    pub async fn launch_discovery(&mut self, handler: Arc<Mutex<ZenohHandler>>) {
        let mut session_discover = self.clone();
        let keep_running_discover = self.running.clone();
        let discovery_interval_seconds = self.discovery_interval_seconds;
        let _zc = self.middleware_config.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let mut keep_running;
            {
                keep_running = *keep_running_discover.lock().await;
            }
            while keep_running {
                let _ = session_discover.discover(handler.clone()).await;
                tokio::time::sleep(Duration::from_secs(discovery_interval_seconds)).await;
                {
                    keep_running = *keep_running_discover.lock().await;
                }
            }
        });
    }

    pub async fn launch_replay(&mut self, handler: Arc<Mutex<ZenohHandler>>) {
        let mut session_discover = self.clone();
        let keep_running_discover = self.running.clone();
        let discovery_interval_seconds = self.discovery_interval_seconds;
        let _zc = self.middleware_config.clone();
        let handler = handler.clone();
        let sessions_clone = self.sessions.clone();
        tokio::spawn(async move {
            let mut keep_running;
            {
                keep_running = *keep_running_discover.lock().await;
            }
            while keep_running {
                {
                    let sessions;
                    let session_ids: Vec<String>;
                    {
                        sessions = sessions_clone.lock().await;
                        session_ids = sessions.iter().map(|(key, _)| key.to_string()).collect();
                    }
                    for session_id in session_ids {
                        let _ = session_discover.replay(handler.clone(), &session_id).await;
                    }
                }

                tokio::time::sleep(Duration::from_secs(discovery_interval_seconds)).await;
                {
                    keep_running = *keep_running_discover.lock().await;
                }
            }
        });
    }

    pub async fn terminate_session_locally(&mut self, session_id: &str) {
        let _signature = match self.host_encro.lock().await.sign(session_id) {
            Ok(s) => s,
            Err(_) => {
                return;
            }
        };
        let other_pub_key = self.get_pub_key_from_session_id(session_id).await;
        if other_pub_key.is_err() {
            return;
        }
        let other_pub_key = other_pub_key.unwrap();
        let pub_key_decoded = match base64::decode(other_pub_key) {
            Err(_) => {
                return;
            }
            Ok(pub_key) => pub_key,
        };
        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
            Ok(pub_encro) => {
                let _pub_key = self.host_encro.lock().await.get_public_key_as_base64();
                let _topic = Topic::close_topic(&pub_encro.get_public_key_fingerprint());

                let mut hm = self.sessions.lock().await;
                hm.remove(session_id);

                let _ = self
                    .call_callbacks_session_closed(
                        &pub_encro.get_public_key_as_base64(),
                        session_id,
                    )
                    .await;
            }
            Err(_) => {
                return;
            }
        }
    }

    pub async fn terminate_session(&mut self, session_id: &str, sender: Arc<Mutex<ZenohHandler>>) {
        let signature = match self.host_encro.lock().await.sign(session_id) {
            Ok(s) => s,
            Err(_) => {
                return;
            }
        };
        let other_pub_key = self.get_pub_key_from_session_id(session_id).await;
        if other_pub_key.is_err() {
            return;
        }
        let other_pub_key = other_pub_key.unwrap();
        let pub_key_decoded = match base64::decode(other_pub_key) {
            Err(_) => {
                return;
            }
            Ok(pub_key) => pub_key,
        };
        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
            Ok(pub_encro) => {
                let pub_key = self.host_encro.lock().await.get_public_key_as_base64();
                let msg = Message::new_close(session_id.to_string(), pub_key, signature);
                let topic = Topic::close_topic(&pub_encro.get_public_key_fingerprint());
                {
                    let sender = sender.lock().await;
                    let _ = sender.send_message(&topic, msg).await;
                }

                let mut hm = self.sessions.lock().await;
                hm.remove(session_id);

                let _ = self
                    .call_callbacks_session_closed(
                        &pub_encro.get_public_key_as_base64(),
                        session_id,
                    )
                    .await;
            }
            Err(_) => {
                return;
            }
        }
    }

    pub async fn launch_session_housekeeping(&mut self, sender: Arc<Mutex<ZenohHandler>>) {
        let mut session_discover = self.clone();
        let keep_running_discover = self.running.clone();
        let heartbeat_interval_seconds = self.heartbeat_interval_seconds;
        let _zc = self.middleware_config.clone();
        let wait_factor = 10; // 5 times the discovery interval, hard coded for now?
        let handler = sender.clone();
        tokio::spawn(async move {
            let mut keep_running;
            {
                keep_running = *keep_running_discover.lock().await;
            }

            while keep_running {
                let sessions;
                {
                    sessions = session_discover.get_sessions().await;
                }
                let mut session_ids = Vec::new();
                for (session_id, session_data) in sessions.iter() {
                    let now = SystemTime::now();
                    let last_active = session_data.last_active;
                    let duration = now.duration_since(last_active).unwrap();
                    if duration.as_secs() > heartbeat_interval_seconds * wait_factor {
                        let _ = session_discover
                            .terminate_session(&session_id.clone(), handler.clone())
                            .await;
                    }
                    session_ids.push((session_id.clone(), session_data.pub_key.clone()));
                }
                for (session_id, pub_key) in session_ids {
                    let pub_key_decoded = match base64::decode(pub_key) {
                        Err(_) => Err(()),
                        Ok(pub_key) => Ok(pub_key),
                    };
                    if pub_key_decoded.is_err() {
                        continue;
                    }
                    let pub_key_decoded = pub_key_decoded.unwrap();
                    match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
                        Ok(pub_encro) => {
                            let fingerprint = pub_encro.get_public_key_fingerprint();
                            let msg = Message::new_heartbeat(session_id);
                            let topic = Topic::heartbeat_topic(&fingerprint);
                            {
                                let handler = handler.lock().await;
                                let _ = handler.send_message(&topic, msg).await;
                            }
                        }
                        Err(_) => {}
                    }
                }
                tokio::time::sleep(Duration::from_secs(heartbeat_interval_seconds)).await;
                {
                    keep_running = *keep_running_discover.lock().await;
                }
            }
        });
    }

    pub fn set_discovery_interval_seconds(&mut self, interval_seconds: u64) {
        self.discovery_interval_seconds = interval_seconds;
    }

    pub async fn launch_replay_request(&mut self, handler: Arc<Mutex<ZenohHandler>>) {
        let key_fingerprint = self.host_encro.lock().await.get_public_key_fingerprint();
        let handler = handler.clone();
        tokio::spawn(async move {
            // Give it some time for infra to be set up
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Send request for replay
            let replay_topic = Topic::replay_topic(&key_fingerprint);
            let message = Message::new_replay(key_fingerprint);
            let _ = handler
                .lock()
                .await
                .send_message(&replay_topic, message)
                .await;
        });
    }

    pub async fn serve(&mut self) -> Result<(), MessagingError> {
        let mut identifier = self.host_encro.lock().await.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        if self.relay {
            identifier = "**".to_string();
        }

        // the initialization topic
        let init_topic = Topic::init_topic(identifier.as_ref());
        let close_topic = Topic::close_topic(identifier.as_ref());
        let discover_topic = Topic::Discover.to_string();
        let heartbeat_topic = Topic::heartbeat_topic(identifier.as_ref());

        if self.relay {
            let email_topic = Topic::email_topic(identifier.as_ref());
            let replay_topic = Topic::replay_topic(identifier.as_ref());
            topics_to_subscribe.push(email_topic);
            topics_to_subscribe.push(replay_topic);
            topics_to_subscribe.push(init_topic);
        } else {
            let replay_response_topic = Topic::replay_response_topic(identifier.as_ref());
            topics_to_subscribe.push(init_topic);
            topics_to_subscribe.push(close_topic);
            topics_to_subscribe.push(discover_topic);
            topics_to_subscribe.push(heartbeat_topic);
            topics_to_subscribe.push(replay_response_topic);
        }

        let tx_clone = self.tx.clone();
        self.serve_topics(topics_to_subscribe, &tx_clone, false)
            .await;
        let zc = self.middleware_config.clone();
        let zenoh_session;
        {
            let zenoh_config = Config::from_file(zc).unwrap();
            zenoh_session = zenoh::open(zenoh_config).await;
        }
        if zenoh_session.is_err() {
            return Err(MessagingError::ZenohError);
        }
        let zenoh_session = zenoh_session.unwrap();
        let zenoh_session_responder = Arc::new(Mutex::new(zenoh_session));
        let responder = Arc::new(Mutex::new(ZenohHandler::new(zenoh_session_responder)));

        if !self.relay {
            // Send discover message each minut
            self.launch_discovery(responder.clone()).await;
            // Launch session housekeeping
            self.launch_session_housekeeping(responder.clone()).await;
            // Launch memory retrieval task
            self.launch_replay_request(responder.clone()).await;
        }
        let keep_running = self.running.clone();
        let relay_file = ".relay".to_string();
        let mut relay = SessionRelay::from_file(&relay_file)
            .unwrap_or_else(|_| SessionRelay::new(relay_file, 54, 124));
        let duration_wait = 60;
        let mut relay_last_stored = Utc::now();
        while *keep_running.lock().await {
            let timeout_duration = Duration::from_secs(duration_wait);
            let received = match timeout(timeout_duration, self.rx.lock().await.recv()).await {
                Ok(Some(received)) => Some(received),
                Ok(None) => None,
                Err(_) => {
                    // Timeout occurred, continue to the next iteration of the loop
                    None
                }
            };
            if self.relay {
                // check if we want to store the relay
                if relay_last_stored < relay.last_active
                    && (relay.last_active - relay_last_stored).num_seconds().abs() > 60
                {
                    println!("storing to file..");
                    let _ = relay.to_file();
                    relay_last_stored = relay.last_active;
                }
            }

            if received.is_none() {
                continue;
            }

            let received = received.unwrap();
            let topic = received.0;
            let mut topic_error = Topic::Errors.as_str().to_string();
            topic_error.push_str("/");
            topic_error.push_str(&identifier);
            let _msg = match Message::deserialize(&received.1) {
                Ok(msg) => {
                    let session_id = msg.session_id.clone();
                    if topic == "internal" {
                        match msg.message {
                            Internal(ref msg) => {
                                if msg.message == "terminate" {
                                    self.close_sessions(responder.clone()).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    match self.handle_message(msg, &topic, &mut relay, false).await {
                        Ok(Some(res)) => {
                            // Do something
                            let response = res.0;
                            let topic_response = res.1;
                            if topic_response == "terminate" {
                                *keep_running.lock().await = false;
                                continue;
                            }
                            let _ = response.clone();
                            let responder = responder.lock().await;
                            let _ = responder
                                .send_message(&topic_response, response.clone())
                                .await;
                        }
                        Ok(None) => {}
                        Err(errormessage) => {
                            //println!("errormessage {:?}", errormessage);
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id,
                            };
                            let _ = response.to_string();
                            if !self.relay {
                                let responder = responder.lock().await;
                                let _ = responder.send_message(&topic_error, response).await;
                            }
                        }
                    }
                }
                Err(_) => {}
            };
        }

        self.close_sessions(responder).await;

        if self.memory_active {
            let _ = self.memory.lock().await.to_file();
        }
        return Ok(());
    }

    pub async fn close_sessions(&mut self, sender: Arc<Mutex<ZenohHandler>>) {
        let sessions;
        {
            sessions = self.get_sessions().await;
        }
        for (session_id, _session_data) in sessions.iter() {
            let _ = self.terminate_session(session_id, sender.clone()).await;
        }
    }

    pub async fn stop_session(&mut self) {
        *self.running.lock().await = false;
    }

    pub async fn get_discovered(&self) -> Vec<String> {
        let discovered;
        {
            discovered = self.discovered.lock().await;
        }
        let mut discovered_keys = Vec::new();
        for (_fingerprint, key) in discovered.iter() {
            discovered_keys.push(key.clone());
        }
        discovered_keys
    }

    pub async fn discover(
        &mut self,
        sender: Arc<Mutex<ZenohHandler>>,
    ) -> Result<(), MessagingError> {
        let discover_topic = Topic::Discover.as_str();
        let mut discover_topic_reply = discover_topic.to_string();
        discover_topic_reply.push_str(Topic::reply_suffix());
        let _timeout_discovery = Duration::from_secs(5);

        let this_pub_key;
        {
            this_pub_key = Some(self.host_encro.lock().await.get_public_key_as_base64());
        }
        let msg = Message::new_discovery(this_pub_key.clone().unwrap());
        {
            let h = sender.lock().await;
            h.send_message(discover_topic, msg).await?;
        }
        Ok(())
    }

    pub async fn replay(
        &mut self,
        sender: Arc<Mutex<ZenohHandler>>,
        session_id: &str,
    ) -> Result<(), MessagingError> {
        let topic = Topic::replay_topic(session_id);
        let msg = Message::new_replay(session_id.to_string());
        {
            let h = sender.lock().await;
            h.send_message(&topic, msg).await?;
        }
        Ok(())
    }

    pub async fn send_and_receive_topic<
        T: MessagebleTopicAsync + MessagebleTopicAsyncReadTimeout,
    >(
        &mut self,
        send_msg: Message,
        topic_tx: &str,
        topic_rx: &str,
        timeout: std::time::Duration,
        gateway: &T,
    ) -> Result<Message, MessagingError> {
        match gateway.send_message(topic_tx, send_msg).await {
            Ok(_) => {}
            Err(_error) => return Err(MessagingError::UnreachableHost),
        };
        gateway.read_message_timeout(topic_rx, timeout).await
    }

    pub async fn send_and_multi_receive_topic<
        T: MessagebleTopicAsync + MessagebleTopicAsyncReadTimeout,
    >(
        &mut self,
        send_msg: Message,
        topic_tx: &str,
        topic_rx: &str,
        timeout: std::time::Duration,
        gateway: &T,
    ) -> Result<Vec<Message>, MessagingError> {
        match gateway.send_message(topic_tx, send_msg).await {
            Ok(_) => {}
            Err(_error) => return Err(MessagingError::UnreachableHost),
        };
        gateway.read_messages_timeout(topic_rx, timeout).await
    }

    pub async fn send<T: MessagebleTopicAsync + MessagebleTopicAsyncReadTimeout>(
        &mut self,
        send_msg: Message,
        topic_tx: &str,
        gateway: &T,
    ) -> Result<(), MessagingError> {
        match gateway.send_message(topic_tx, send_msg).await {
            Ok(_) => {}
            Err(_error) => return Err(MessagingError::UnreachableHost),
        };
        Ok(())
    }

    pub fn parse_message(message: &str) -> Result<Message, SessionErrorMsg> {
        let session_message: Message = match Message::deserialize(message) {
            Ok(message) => message,
            Err(_) => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::Serialization as u32,
                    message: "Failed to parse message".to_owned(),
                })
            }
        };

        Ok(session_message)
    }

    pub async fn get_number_of_sessions(&self) -> usize {
        let session = self.sessions.lock().await;
        session.len()
    }

    pub async fn get_session_ids(&self) -> Vec<String> {
        let session = self.sessions.lock().await;
        let mut ids = Vec::new();
        for (id, _) in session.iter() {
            ids.push(id.clone());
        }
        ids
    }

    pub async fn get_nbr_emails(&self) -> u64 {
        return self
            .inbox
            .lock()
            .await
            .get_entries()
            .len()
            .try_into()
            .unwrap();
    }

    pub async fn get_pub_key_from_session_id(&self, session_id: &str) -> Result<String, String> {
        if let Some(session_data) = self.sessions.lock().await.get(session_id) {
            let pub_key = session_data.pub_key.clone();
            Ok(pub_key)
        } else {
            Err("Nope".to_string())
        }
    }

    pub async fn handle_init_ok(
        &mut self,
        msg: InitOkMsg,
        session_id: &str,
        relay: &mut SessionRelay,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let challenge_sig = msg.challenge_sig.clone();
        let sym_key_encrypted = msg.sym_key_encrypted.clone();

        if self.relay {
            relay.register_participant(&msg.pub_key, &session_id);
            relay.register_participant(&msg.orig_pub_key, &session_id);
            return Ok(None);
        }

        let sym_key = match self.host_encro.lock().await.decrypt(&sym_key_encrypted) {
            Ok(res) => res,
            Err(_) => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidPublicKey as u32,
                    message: "Invalid session key".to_owned(),
                });
            }
        };
        let mut add_session = None;
        let _this_pub_key = self.host_encro.lock().await.get_public_key_as_base64();
        {
            let pendings = self.requests_outgoing_initialization.lock().await;
            let pub_key_dec = base64::decode(&msg.pub_key);
            if pub_key_dec.is_err() {
                return Ok(None);
            }
            let pub_key_dec = pub_key_dec.unwrap();
            let cert = read_from_vec(&pub_key_dec);
            if cert.is_err() {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidPublicKey as u32,
                    message: "Invalid key".to_owned(),
                });
            }
            let cert = cert.unwrap();
            let other_key_fingerprint = cert.fingerprint().to_string();

            for (pending_fingerprint, pending_challenge) in pendings.iter() {
                let pending_pub_key_fingerprint = pending_fingerprint.clone();
                if other_key_fingerprint == pending_pub_key_fingerprint {
                    // Add this to the sessions to add
                    let verified = match PGPEnCryptOwned::new_from_vec(&pub_key_dec) {
                        Ok(pub_encro) => {
                            match pub_encro.verify(&challenge_sig, pending_challenge) {
                                Ok(result) => result,
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    };
                    if verified {
                        add_session = Some(msg.pub_key.clone())
                    }
                }
            }
        }

        if add_session.is_some() {
            let add_session_pub_key = add_session.unwrap();
            let pub_key_dec =
                base64::decode(&add_session_pub_key).expect("Failed to decode pub_key");
            let cert = read_from_vec(&pub_key_dec);
            if cert.is_err() {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidPublicKey as u32,
                    message: "Invalid key".to_owned(),
                });
            }
            let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
            let key = session_id;
            let session_data = SessionData {
                id: key.into(),
                last_active: SystemTime::now(),
                state: SessionState::Active,
                messages: Vec::new(),
                sym_encro: cipher,
                sym_key_encrypted_host: sym_key_encrypted.clone(),
                pub_key: add_session_pub_key.clone(),
            };

            let new_session_data = session_data.clone();
            let new_session_id = session_data.id.clone();

            {
                let mut sessions = self.sessions.lock().await;
                sessions.insert(new_session_id.clone(), new_session_data);
                let mut others = Vec::new();
                others.push(add_session_pub_key.clone());
                if self.memory_active {
                    self.memory.lock().await.new_entry(
                        new_session_id.clone(),
                        sym_key_encrypted.clone(),
                        others,
                    );
                }
            }

            self.call_callbacks_init_accepted(&add_session_pub_key.clone())
                .await;

            self.chat(new_session_id.clone(), false, add_session_pub_key.clone())
                .await;
        }
        Ok(None)
    }

    pub async fn handle_init(
        &mut self,
        msg: InitMsg,
        session_id: &str,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        {
            if self.host_encro.lock().await.get_public_key_as_base64() == msg.pub_key {
                return Ok(None);
            }
        }

        if self.relay {
            return Ok(None);
        }
        let signature = msg.signature.clone();
        let challenge = msg.challenge.clone();

        if challenge.len() != challenge_len() {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::Protocol as u32,
                message: "Invalid challenge length".to_owned(),
            });
        }

        let pub_key = msg.pub_key.clone();
        let pub_key_decoded = match base64::decode(msg.pub_key) {
            Err(_) => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidPublicKey as u32,
                    message: "Invalid public key base64".to_owned(),
                });
            }
            Ok(pub_key) => pub_key,
        };
        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
            Ok(pub_encro) => {
                {
                    let other_key = pub_encro.get_public_key_fingerprint();

                    if let Err(_s) = pub_encro.verify(&signature, &other_key) {
                        let msg = Message::new_init_decline(
                            pub_key.clone(),
                            "Invalid signature".to_owned(),
                        );
                        let mut topic_response = Topic::Initialize.as_str().to_string();
                        topic_response.push_str("/");
                        topic_response.push_str(&pub_encro.get_public_key_fingerprint());
                        return Ok(Some((msg, topic_response)));
                    }
                }

                let pub_key = pub_encro.get_public_key_as_base64();

                if self.relay {
                    println!(
                        "-- initmsg {} - session id: {}",
                        pub_encro.get_public_key_fingerprint(),
                        session_id
                    );
                }

                let initialize_this = self.call_callbacks_init_incoming(&pub_key).await;
                let this_pub_key = self.host_encro.lock().await.get_public_key_as_base64();
                if initialize_this {
                    {
                        let sym_cipher = ChaCha20Poly1305EnDeCrypt::new();
                        let sym_cipher_key = sym_cipher.get_public_key_as_base64();
                        let sym_cipher_key_encrypted = match pub_encro.encrypt(&sym_cipher_key) {
                            Ok(res) => res,
                            Err(_) => {
                                return Err(SessionErrorMsg {
                                    code: SessionErrorCodes::Encryption as u32,
                                    message: "Failed to encrypt session key".to_owned(),
                                });
                            }
                        };
                        let sym_cipher_key_encrypted_host =
                            match self.host_encro.lock().await.encrypt(&sym_cipher_key) {
                                Ok(res) => res,
                                Err(_) => {
                                    return Err(SessionErrorMsg {
                                        code: SessionErrorCodes::Encryption as u32,
                                        message: "Failed to encrypt session key".to_owned(),
                                    });
                                }
                            };
                        let pk_1 = pub_encro.get_public_key_fingerprint();
                        let pk_2 = self.host_encro.lock().await.get_public_key_fingerprint();

                        let s = pk_1.clone() + &pk_2;
                        let key = sha256sum(&s);
                        let pub_key = pub_encro.get_public_key_as_base64();

                        let challenge_sig = match self.host_encro.lock().await.sign(&challenge) {
                            Ok(s) => s,
                            Err(_e) => {
                                return Err(SessionErrorMsg {
                                    code: SessionErrorCodes::Encryption as u32,
                                    message: "Failed to create signature of challenge".to_owned(),
                                });
                            }
                        };

                        let session_data = SessionData {
                            id: key.clone(),
                            last_active: SystemTime::now(),
                            state: SessionState::Initializing,
                            pub_key: pub_key.clone(),
                            messages: Vec::new(),
                            sym_encro: sym_cipher,
                            sym_key_encrypted_host: sym_cipher_key_encrypted_host.clone(),
                        };
                        let mut msg = Message::new_init_ok(
                            sym_cipher_key_encrypted.clone(),
                            this_pub_key.clone(),
                            pub_encro.get_public_key_as_base64(),
                            challenge_sig,
                        );
                        msg.session_id = key.clone();

                        if self.memory_active {
                            // Store conversation in memory
                            let mut others = Vec::new();
                            others.push(pub_encro.get_public_key_as_base64());

                            self.memory.lock().await.new_entry(
                                msg.session_id.clone(),
                                sym_cipher_key_encrypted_host.clone(),
                                others,
                            );
                        }

                        let mut hm = self.requests_incoming_initialization.lock().await;
                        let mut topic_response = Topic::Initialize.as_str().to_string();
                        topic_response.push_str("/");
                        topic_response.push_str(&pub_encro.get_public_key_fingerprint());
                        hm.push((session_data, msg, topic_response));
                    }
                    let mut topic_response = Topic::Initialize.as_str().to_string();
                    topic_response.push_str("/");
                    topic_response.push_str(&pub_encro.get_public_key_fingerprint());
                    let msg = Message::new_init_await(
                        pub_encro.get_public_key_as_base64(),
                        this_pub_key.clone(),
                    );
                    Ok(Some((msg, topic_response)))
                } else {
                    let mut topic_response = Topic::Initialize.as_str().to_string();
                    topic_response.push_str("/");
                    topic_response.push_str(&pub_encro.get_public_key_fingerprint());
                    let msg = Message::new_init_decline(
                        pub_encro.get_public_key_as_base64(),
                        this_pub_key.clone(),
                    );
                    Ok(Some((msg, topic_response)))
                }
            }
            Err(_) => Err(SessionErrorMsg {
                code: SessionErrorCodes::InvalidPublicKey as u32,
                message: "Invalid public key".to_owned(),
            }),
        }
    }

    pub async fn handle_discovery(
        &mut self,
        msg: DiscoveryMsg,
        session_id: &str,
        topic: &str,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let pub_key = msg.pub_key.clone();

        if pub_key == self.host_encro.lock().await.get_public_key_as_base64() || self.relay {
            return Ok(None);
        }

        let pub_key_dec = base64::decode(&pub_key);
        if pub_key_dec.is_err() {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::InvalidPublicKey as u32,
                message: "Invalid public key".to_owned(),
            });
        }
        let pub_key_dec = pub_key_dec.unwrap();
        let discovered_cert = read_from_vec(&pub_key_dec);
        if discovered_cert.is_err() {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::InvalidPublicKey as u32,
                message: "Invalid public key".to_owned(),
            });
        }
        let discovered_cert = discovered_cert.unwrap();
        let discovered_pub_key_fingerprint = discovered_cert.fingerprint().to_string();

        let mut discovered;
        {
            discovered = self.discovered.lock().await;
        }

        let this_fingerprint;
        {
            this_fingerprint = Some(self.host_encro.lock().await.get_public_key_fingerprint());
        }
        let this_fingerprint = this_fingerprint.unwrap();

        if discovered_pub_key_fingerprint != this_fingerprint
            && !discovered.contains_key(&discovered_pub_key_fingerprint)
        {
            let not_ignore = self.call_callbacks_discovered(&pub_key).await;
            if not_ignore {
                discovered.insert(discovered_pub_key_fingerprint, pub_key);
            }
        }

        let mut response =
            Message::new_discovery_reply(self.host_encro.lock().await.get_public_key_as_base64());
        response.session_id = session_id.into();
        Ok(Some((response, topic.to_string())))
    }

    pub async fn handle_discovery_reply(
        &mut self,
        msg: DiscoveryReplyMsg,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let pub_key = msg.pub_key.clone();

        if pub_key == self.host_encro.lock().await.get_public_key_as_base64() {
            return Ok(None);
        }

        let pub_key_dec = base64::decode(&pub_key);
        if pub_key_dec.is_err() {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::InvalidPublicKey as u32,
                message: "Invalid public key".to_owned(),
            });
        }
        let pub_key_dec = pub_key_dec.unwrap();
        let discovered_cert = read_from_vec(&pub_key_dec);
        if discovered_cert.is_err() {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::InvalidPublicKey as u32,
                message: "Invalid public key".to_owned(),
            });
        }
        let discovered_cert = discovered_cert.unwrap();
        let discovered_pub_key_fingerprint = discovered_cert.fingerprint().to_string();

        let mut discovered;
        {
            discovered = self.discovered.lock().await;
        }

        let this_fingerprint;
        {
            this_fingerprint = Some(self.host_encro.lock().await.get_public_key_fingerprint());
        }
        let this_fingerprint = this_fingerprint.unwrap();

        if discovered_pub_key_fingerprint != this_fingerprint
            && !discovered.contains_key(&discovered_pub_key_fingerprint)
        {
            let not_ignore = self.call_callbacks_discovered(&pub_key).await;
            if not_ignore {
                discovered.insert(discovered_pub_key_fingerprint, pub_key);
            }
        }

        Ok(None)
    }

    pub async fn handle_encrypted(
        &mut self,
        msg: EncryptedMsg,
        topic: &str,
        session_id: &str,
        relay: &mut SessionRelay,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let session_key_old = self.memory.lock().await.get_encrypted_sym_key(&session_id);
        if session_key_old.is_ok() {
            // decrypt the encrypted symmetrical key
            let session_key_old = session_key_old.unwrap();
            let sym_key = self.decrypt_encrypted_str(session_key_old).await;
            if sym_key.is_ok() {
                let sym_key = sym_key.unwrap();
                let dec_msg = self
                    .decrypt_sym_encrypted_msg(sym_key.clone(), msg.data.clone())
                    .await;

                if dec_msg.is_ok() {
                    let dec_msg = dec_msg.unwrap();
                    let _ = self.handle_message(dec_msg, topic, relay, true).await;
                }
            }
        }

        let dec_msg;
        {
            let sm = &self.sessions.lock().await;
            let cipher = match sm.get(session_id) {
                Some(m) => m.sym_encro.clone(),
                None => {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::InvalidMessage as u32,
                        message: "Invalid session id".to_owned(),
                    });
                }
            };
            let decrypted = match cipher.decrypt(&msg.data) {
                Ok(res) => res,
                Err(_) => {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::Encryption as u32,
                        message: "Failed to decrypt message".to_owned(),
                    });
                }
            };
            dec_msg = Some(match Message::deserialize(&decrypted) {
                Ok(m) => m,
                Err(_) => {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::Serialization as u32,
                        message: "Failed to parse message".to_owned(),
                    });
                }
            });
        }
        if dec_msg.is_some() {
            let dec_msg = dec_msg.unwrap();
            self.handle_message(dec_msg, topic, relay, true).await
        } else {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::Encryption as u32,
                message: "Failed to decrypt message".to_owned(),
            });
        }
    }

    pub async fn handle_internal(
        &mut self,
        msg: InternalMsg,
        topic: &str,
        session_id: &str,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        if topic == Topic::Internal.as_str() {
            if session_id == "internal" && msg.message == "terminate" {
                self.call_callbacks_terminate().await;
                *self.running.lock().await = false;
                return Ok(None);
            }

            let message = Message {
                message: MessageData::Chat(ChatMsg {
                    message: msg.message.to_string(),
                    sender_userid: self.get_userid().await,
                    sender_fingerprint: self.host_encro.lock().await.get_public_key_fingerprint(),
                    date_time: get_current_datetime(),
                }),
                session_id: session_id.into(),
            };
            let msg_enc = self.encrypt_msg(&session_id, &message).await;
            if msg_enc.is_ok() {
                let msg_enc = msg_enc.unwrap();

                let message = Message {
                    message: MessageData::Encrypted(msg_enc),
                    session_id: session_id.into(),
                };
                let topic_response = msg.topic;

                let pk = self.host_encro.lock().await.get_public_key_as_base64();
                self.call_callbacks_chat(&pk, &msg.message).await;
                return Ok(Some((message, topic_response)));
            } else {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::Protocol as u32,
                    message: "Session not found".to_owned(),
                });
            }
        } else {
            return Err(SessionErrorMsg {
                code: SessionErrorCodes::Protocol as u32,
                message: "Invalid internal message topic".to_owned(),
            });
        }
    }

    #[async_recursion]
    pub async fn handle_message(
        &mut self,
        message: Message,
        topic: &str,
        relay: &mut SessionRelay,
        has_been_decypted: bool,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let topic_response = topic.to_string();
        let mut response = Message::new_discovery("Hello world".to_string());
        response.session_id = message.session_id.clone();
        let session_id = message.session_id.clone();
        let incoming_message = message.clone();

        match message.message {
            Internal(msg) => {
                return self.handle_internal(msg, topic, &session_id).await;
            }
            ReplayResponse(msg) => {
                if self.relay {
                    return Ok(None);
                }
                //self.added_emails.lock().await += 1337;
                for message in msg.messages {
                    let v = *self.added_emails.lock().await;
                    *self.added_emails.lock().await = v + 1;
                    let _ = self
                        .handle_message(message, topic, relay, has_been_decypted)
                        .await;
                }
                return Ok(None);
            }
            Replay(msg) => {
                if !self.relay {
                    return Ok(None);
                }
                if let Some(messages) = relay.get_messages(&msg.key_id) {
                    let topic = Topic::replay_response_topic(&msg.key_id);
                    return Ok(Some((
                        Message::new_replay_response(msg.key_id, messages),
                        topic,
                    )));
                } else {
                }
                return Ok(None);
            }
            DiscoveryReply(msg) => {
                return self.handle_discovery_reply(msg).await;
            }
            Heartbeat(_msg) => {
                if let Some(session_data) = self.sessions.lock().await.get_mut(&session_id) {
                    session_data.last_active = SystemTime::now();
                }
                Ok(None)
            }
            Discovery(msg) => {
                return self.handle_discovery(msg, &session_id, &topic).await;
            }
            Init(msg) => {
                return self.handle_init(msg, &session_id).await;
            }
            InitAwait(msg) => {
                self.call_callbacks_init_await(&msg.pub_key).await;
                Ok(None)
            }
            InitDecline(msg) => {
                self.call_callbacks_init_declined(&msg.pub_key, &msg.message)
                    .await;
                Ok(None)
            }
            InitOk(msg) => {
                return self.handle_init_ok(msg, &session_id, relay).await;
            }
            Close(_msg) => {
                let session_id = message.session_id.clone();
                let fingerprint = self.get_pub_key_from_session_id(&session_id).await;
                if fingerprint.is_ok() {
                    self.terminate_session_locally(&session_id).await;
                }
                Ok(None)
            }
            Ping(_msg) => Ok(Some((response, topic_response))),
            Chat(msg) => {
                if let Some(session_data) = self.sessions.lock().await.get(&session_id) {
                    let pub_key = session_data.pub_key.clone();
                    self.call_callbacks_chat(&pub_key, &msg.message).await;
                    if self.memory_active {
                        let _ = self
                            .memory
                            .lock()
                            .await
                            .add_entry_message(&session_id.clone(), incoming_message.clone());
                    }
                    return Ok(None);
                } else if self.memory.lock().await.in_memory(&session_id) {
                    let _ = self
                        .memory
                        .lock()
                        .await
                        .add_entry_message(&session_id, incoming_message.clone());
                    Ok(None)
                } else {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::InvalidPublicKey as u32,
                        message: "Invalid public key".to_owned(),
                    });
                }
            }
            EncryptedRelay(msg) => {
                if self.relay {
                    let msg = Message {
                        message: MessageData::Encrypted(EncryptedMsg { data: msg.data }),
                        session_id: session_id.to_string(),
                    };
                    if let Some(messages_in_session) = relay.put_message(session_id.clone(), msg) {
                        println!(
                            "{} session {} has {} messages in memory",
                            get_current_datetime(),
                            session_id,
                            messages_in_session
                        );
                    } else {
                        println!("failed to add message to session {}", session_id);
                    }
                }
                return Ok(None);
            }
            Encrypted(msg) => {
                return self.handle_encrypted(msg, topic, &session_id, relay).await;
            }
            Email(msg) => {
                if !has_been_decypted {
                    return Ok(None);
                }
                let session_id = msg.session_id.clone();
                if !self.relay {
                    // Store this in memory if it exists
                    if self.memory.lock().await.in_memory(&session_id) {
                        self.inbox.lock().await.add_entry(msg.clone());
                        let _ = self.inbox.lock().await.to_file();
                    }
                }
                Ok(None)
            }
            _ => {
                // Do something
                Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidMessage as u32,
                    message: "Invalid message type".to_owned(),
                })
            }
        }
    }

    pub async fn decrypt_encrypted_str(&self, secret: String) -> Result<String, ()> {
        match self.host_encro.lock().await.decrypt(&secret) {
            Ok(res) => Ok(res),
            Err(_) => Err(()),
        }
    }

    pub async fn decrypt_sym_encrypted_str(
        &self,
        sym_key: String,
        secret: String,
    ) -> Result<String, ()> {
        let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
        match cipher.decrypt(&secret) {
            Ok(res) => Ok(res),
            Err(_) => Err(()),
        }
    }
    pub async fn decrypt_sym_encrypted_msg(
        &self,
        sym_key: String,
        secret: String,
    ) -> Result<Message, ()> {
        let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
        let msg = match cipher.decrypt(&secret) {
            Ok(res) => res,
            Err(_) => return Err(()),
        };
        match Message::deserialize(&msg) {
            Ok(m) => Ok(m),
            Err(_) => Err(()),
        }
    }

    async fn decrypt_encrypted_msg(
        &self,
        session_id: String,
        msg: EncryptedMsg,
    ) -> Result<Message, SessionErrorMsg> {
        let sm = &self.sessions.lock().await;
        let cipher = match sm.get(&session_id) {
            Some(m) => m.sym_encro.clone(),
            None => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::InvalidMessage as u32,
                    message: "Invalid session id".to_owned(),
                });
            }
        };
        let decrypted = match cipher.decrypt(&msg.data) {
            Ok(res) => res,
            Err(_) => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::Encryption as u32,
                    message: "Failed to decrypt message".to_owned(),
                });
            }
        };
        match Message::deserialize(&decrypted) {
            Ok(m) => return Ok(m),
            Err(_) => {
                return Err(SessionErrorMsg {
                    code: SessionErrorCodes::Serialization as u32,
                    message: "Failed to parse message".to_owned(),
                });
            }
        }
    }
    pub async fn get_fingerprint(&self) -> String {
        self.host_encro.lock().await.get_public_key_fingerprint()
    }
    pub async fn get_userid(&self) -> String {
        self.host_encro.lock().await.get_userid()
    }
    pub async fn get_others_peers(&self, session_id: &str) -> Option<Vec<String>> {
        let session = self.sessions.lock().await;
        let session_data = session.get(session_id);
        if session_data.is_none() {
            return None;
        }
        let session_data = session_data.unwrap();

        let other_pub_key = session_data.pub_key.clone();
        let pub_key_decoded = match base64::decode(other_pub_key) {
            Err(_) => {
                return None;
            }
            Ok(pub_key) => pub_key,
        };
        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
            Ok(pub_encro) => {
                let mut v = Vec::new();
                v.push(pub_encro.get_userid());
                return Some(v);
            }
            Err(_) => {
                return None;
            }
        }
    }
    pub async fn get_sym_key_host_encryted(&self, session_id: &str) -> Option<String> {
        let session = self.sessions.lock().await;
        let session_data = match session.get(session_id) {
            Some(entry) => entry,
            None => {
                return None;
            }
        };
        Some(session_data.sym_key_encrypted_host.clone())
    }

    pub async fn get_reminded_session_ids(&self) -> Vec<String> {
        self.memory.lock().await.get_session_ids()
    }
    pub async fn get_reminded_length(&self, session_id: &str) -> Result<usize, ()> {
        self.memory.lock().await.get_length(session_id)
    }
    pub async fn get_reminded_others(&self, session_id: &str) -> Result<Vec<String>, ()> {
        self.memory.lock().await.get_others(session_id)
    }
    pub async fn get_reminded_last_active(&self, session_id: &str) -> Result<String, ()> {
        self.memory.lock().await.get_last_active(session_id)
    }
    pub async fn remove_memory_entry(&self, session_id: &str) -> Result<usize, ()> {
        self.memory.lock().await.delete_session(session_id)
    }
    pub async fn get_reminded_session_log(
        &self,
        session_id: &str,
    ) -> Result<(String, Vec<SessionLogMessage>), ()> {
        self.memory.lock().await.get_session_log(session_id)
    }

    fn extract_subject(content: &str) -> String {
        let subject_regex = Regex::new(r"(?i)subject:\s*(.*)").unwrap(); // (?i) makes it case-insensitive
        if let Some(captures) = subject_regex.captures(content) {
            captures
                .get(1) // Get the first capturing group, which is the "[the rest of the line]"
                .map_or("No subject".to_string(), |m| m.as_str().to_string())
        } else {
            "No subject".to_string()
        }
    }

    pub async fn send_email<T: MessagebleTopicAsync + MessagebleTopicAsyncReadTimeout>(
        &self,
        session_id: &str,
        message: String,
        gateway: &T,
    ) -> Result<(), ()> {
        let topic = Topic::email_topic(&session_id);
        let session_key_old = self.memory.lock().await.get_encrypted_sym_key(&session_id);
        let subject = Self::extract_subject(&message);
        if session_key_old.is_ok() {
            // decrypt the encrypted symmetrical key
            let session_key_old = session_key_old.unwrap();
            let sym_key = self.decrypt_encrypted_str(session_key_old).await;
            if sym_key.is_ok() {
                let sym_key = sym_key.unwrap();
                let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);

                let email = EmailMsg {
                    session_id: session_id.to_owned(),
                    sender: self.get_userid().await,
                    message: message.clone(),
                    subject: subject.clone(),
                    date_time: get_current_datetime(),
                };
                let msg = Message {
                    message: MessageData::Email(email),
                    session_id: session_id.to_string(),
                };
                let email_ser = msg.serialize().unwrap();

                let msg_encrypted = match cipher.encrypt(&email_ser) {
                    Ok(m) => m,
                    Err(_) => {
                        return Err(());
                    }
                };
                let msg = Message {
                    message: MessageData::EncryptedRelay(EncryptedRelayMsg {
                        data: msg_encrypted,
                    }),
                    session_id: session_id.to_string(),
                };
                match gateway.send_message(&topic, msg).await {
                    Ok(_) => {}
                    Err(_error) => return Err(()),
                };
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRelayEntry {
    pub buffer: RingBuffer<Message>,
    pub last_active: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRelay {
    pub memory: HashMap<String, SessionRelayEntry>,
    pub keys_to_sessions: HashMap<String, Vec<String>>,
    pub max_sessions: usize,
    pub max_messages: usize,
    pub file: String,
    pub last_active: DateTime<Utc>,
}

impl SessionRelayEntry {
    pub fn new(max_messages: usize) -> Self {
        Self {
            buffer: RingBuffer::new(max_messages),
            last_active: Utc::now(),
        }
    }
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn push(&mut self, message: Message) -> usize {
        self.buffer.push(message);
        self.last_active = Utc::now();
        self.buffer.len()
    }
}

impl SessionRelay {
    pub fn new(file: String, max_sessions: usize, max_messages: usize) -> Self {
        Self {
            file,
            memory: HashMap::new(),
            keys_to_sessions: HashMap::new(),
            max_messages,
            max_sessions,
            last_active: Utc::now(),
        }
    }
    /// Serializes the Memory struct to an array of bytes using CBOR.
    fn serialize(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("Failed to serialize Memory")
    }
    /// Reads the serialized content from a file at the given path and deserializes it into a Memory struct.
    pub fn from_file(path: &str) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let relay: SessionRelay =
            serde_cbor::from_slice(&buffer).expect("Failed to deserialize Memory");
        Ok(relay)
    }
    /// Writes the serialized content of Memory to a file at the given path.
    pub fn to_file(&self) -> io::Result<()> {
        let serialized = self.serialize();
        let mut file = File::create(&self.file)?;
        file.write_all(&serialized)?;
        Ok(())
    }
    pub fn get_messages(&self, key_id: &str) -> Option<Vec<Message>> {
        let mut messages = Vec::new();
        for session_id in self.get_participant_session_ids(key_id) {
            match self.memory.get(&session_id) {
                Some(memory) => {
                    let buffer = memory.buffer.clone();
                    for i in 0..buffer.len() {
                        messages.push(buffer.get(i).unwrap().clone());
                    }
                }
                None => {}
            }
        }
        if messages.len() == 0 {
            None
        } else {
            Some(messages)
        }
    }
    pub fn put_message(&mut self, session_id: String, message: Message) -> Option<usize> {
        self.last_active = Utc::now();
        match self.memory.get_mut(&session_id) {
            Some(memory) => Some(memory.push(message)),
            None => {
                if self.memory.len() >= self.max_sessions {
                    if let Some((session_id_newest, _)) = self.oldest_entry() {
                        self.remove_entry(&session_id_newest);
                    }
                }
                let mut entry = SessionRelayEntry::new(self.max_messages);
                entry.push(message);
                self.memory.insert(session_id, entry);
                return Some(1);
            }
        }
    }
    pub fn oldest_entry(&self) -> Option<(String, SessionRelayEntry)> {
        let oldest_entry = self
            .memory
            .iter()
            .min_by_key(|(_, entry)| entry.last_active);
        if let Some((session_id, entry)) = oldest_entry {
            return Some((session_id.to_string(), entry.clone()));
        }
        None
    }
    pub fn remove_entry(&mut self, session_id: &str) {
        self.memory.remove(session_id);
    }
    pub fn get_participant_session_ids(&self, key: &str) -> Vec<String> {
        match self.keys_to_sessions.get(key) {
            Some(ids) => {
                return ids.clone();
            }
            None => {
                return Vec::new();
            }
        }
    }
    pub fn register_participant(&mut self, key: &str, session_id: &str) {
        let pub_key_decoded = match base64::decode(key) {
            Err(_) => {
                return;
            }
            Ok(pub_key) => pub_key,
        };
        match PGPEnCryptOwned::new_from_vec(&pub_key_decoded) {
            Ok(pub_encro) => {
                let key = pub_encro.get_public_key_fingerprint();
                match self.keys_to_sessions.get_mut(&key) {
                    Some(ids) => {
                        if ids.contains(&session_id.to_string()) {
                            ids.push(session_id.to_string());
                        }
                    }
                    None => {
                        let mut vec = Vec::new();
                        vec.push(session_id.to_string());
                        self.keys_to_sessions.insert(key.to_string(), vec);
                    }
                }
            }
            Err(_) => {
                return;
            }
        }
    }
}
