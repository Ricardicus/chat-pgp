use std::collections::HashMap;

use std::pin::Pin;
use std::sync::Arc;

use std::time::SystemTime;
use tokio::sync::{mpsc, Mutex};

use tokio::time::{timeout, Duration};

pub mod crypto;
pub mod messages;
pub mod middleware;
pub mod protocol;

use protocol::*;

use crypto::{
    sha256sum, ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalDecrypt, CrypticalEncrypt,
    CrypticalID, CrypticalSign, CrypticalVerify, PGPEnCryptOwned, PGPEnDeCrypt,
};

use messages::MessageData::{
    Chat, Close, Discovery, DiscoveryReply, Encrypted, Heartbeat, Init, InitAwait, InitDecline,
    InitOk, Internal, Ping,
};
use messages::MessagingError::*;
use messages::SessionMessage as Message;
use messages::{
    ChatMsg, EncryptedMsg, InitMsg, MessageData, MessageListener, Messageble, MessagebleTopicAsync,
    MessagebleTopicAsyncPublishReads, MessagebleTopicAsyncReadTimeout, MessagingError,
    SessionErrorCodes, SessionErrorMsg,
};
use middleware::ZenohHandler;

use crate::pgp::pgp::read_from_vec;

use async_recursion::async_recursion;
use futures::prelude::*;
use zenoh::prelude::r#async::*;
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
    running: Arc<Mutex<bool>>,
}

impl Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt> {
    pub fn new(host_encro: PGPEnDeCrypt, middleware_config: String) -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        let (tx_chat, rx_chat) = mpsc::channel(100);
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
        {
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
    }

    pub async fn accept_pending_request(&mut self, session_id: &str) -> Result<(), ()> {
        let mut session_data_incoming = None;
        let mut session_init_ok_msg = None;
        let mut session_init_ok_msg_topic = None;
        {
            let mut requests = self.requests_incoming_initialization.lock().await;
            let mut index = None;

            for (i, (session_data, message, topic)) in requests.iter().enumerate() {
                let id = session_data.id.clone();
                if id == session_id {
                    session_init_ok_msg = Some(message.clone());
                    session_data_incoming = Some(session_data.clone());
                    session_init_ok_msg_topic = Some(topic.clone());
                    index = Some(i);
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
        let fingerprint = cert.fingerprint().to_string();

        {
            let mut hm = self.sessions.lock().await;
            hm.insert(key.clone(), session_data.clone());
        }

        if session_init_ok_msg.is_some() {
            let zc = self.middleware_config.clone();
            let zenoh_config = Config::from_file(zc).unwrap();
            let zenoh_session =
                Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
            let handler = ZenohHandler::new(zenoh_session);
            let msg = session_init_ok_msg.unwrap().clone();
            let _ = self
                .send(msg, session_init_ok_msg_topic.unwrap().as_str(), &handler)
                .await;
            self.chat(key.clone(), &fingerprint, false, pub_key).await;
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
                return self
                    .send(
                        Message::new_from_data(session_id.to_string(), MessageData::Encrypted(msg)),
                        topic,
                        gateway,
                    )
                    .await;
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

    pub async fn initialize_session_zenoh(&mut self, pub_key: String) -> Result<String, String> {
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
        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session = Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
        let handler = ZenohHandler::new(zenoh_session);

        let _await_response_interval = Duration::from_secs(60);

        {
            let mut requests = self.requests_outgoing_initialization.lock().await;
            requests.push((other_key_fingerprint.clone(), challenge));
        }

        let _ = handler.send_message(&topic, message).await;
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
            let zc = self.middleware_config.clone();

            let terminate_callbacks = self.callbacks_terminate.clone();
            let running = self.running.clone();
            let h = tokio::spawn(async move {
                let zenoh_config = Config::from_file(zc).unwrap();
                let zenoh_session = zenoh::open(zenoh_config.clone()).res().await;

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

    pub async fn chat(
        &mut self,
        session_id: String,
        other_key_fingerprint: &str,
        blocking: bool,
        other_key: String,
    ) {
        let pub_key_fingerprint = self.host_encro.lock().await.get_public_key_fingerprint();
        let topic_in = Topic::messaging_topic_in(pub_key_fingerprint.as_ref());
        let topic_out = Topic::messaging_topic_in(&other_key_fingerprint);

        let mut topics: Vec<String> = Vec::new();
        topics.push(topic_in);

        let tx_clone = self.tx_chat.clone();
        self.serve_topics(topics, &tx_clone, false).await;

        let callbacks = self.callbacks_chat.clone();
        let running = self.running.clone();
        let rx_chat = self.rx_chat.clone();
        let rx_session = self.clone();
        let h = tokio::spawn(async move {
            let mut keep_running = *running.lock().await;
            while keep_running {
                let input = rx_chat.lock().await.recv().await;
                if input.is_some() {
                    let (_, msg) = input.unwrap();
                    let mut message_received: Option<String> = None;
                    match Message::deserialize(&msg) {
                        Ok(msg) => match msg.message {
                            Encrypted(msg) => {
                                match rx_session
                                    .decrypt_encrypted_msg(session_id.clone(), msg)
                                    .await
                                {
                                    Ok(msg) => match msg.message {
                                        Chat(msg) => {
                                            message_received = Some(msg.message);
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

    pub async fn serve(&mut self) -> Result<(), MessagingError> {
        let pub_key = self.host_encro.lock().await.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        // the initialization topic
        let init_topic = Topic::init_topic(pub_key.as_ref());
        let close_topic = Topic::close_topic(pub_key.as_ref());
        let discover_topic = Topic::Discover.to_string();
        let heartbeat_topic = Topic::heartbeat_topic(pub_key.as_ref());

        topics_to_subscribe.push(init_topic);
        topics_to_subscribe.push(discover_topic);
        topics_to_subscribe.push(close_topic);
        topics_to_subscribe.push(heartbeat_topic);

        let tx_clone = self.tx.clone();
        self.serve_topics(topics_to_subscribe, &tx_clone, false)
            .await;
        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session = zenoh::open(zenoh_config).res().await;
        if zenoh_session.is_err() {
            return Err(MessagingError::ZenohError);
        }
        let zenoh_session = zenoh_session.unwrap();
        let zenoh_session_responder = Arc::new(Mutex::new(zenoh_session));
        let responder = Arc::new(Mutex::new(ZenohHandler::new(zenoh_session_responder)));
        // Send discover message each minut
        self.launch_discovery(responder.clone()).await;
        // Launch session housekeeping
        self.launch_session_housekeeping(responder.clone()).await;
        let keep_running = self.running.clone();
        while *keep_running.lock().await {
            let timeout_duration = Duration::from_secs(5);
            let received = match timeout(timeout_duration, self.rx.lock().await.recv()).await {
                Ok(Some(received)) => Some(received),
                Ok(None) => None,
                Err(_) => {
                    // Timeout occurred, continue to the next iteration of the loop
                    None
                }
            };
            if received.is_none() {
                continue;
            }
            let received = received.unwrap();
            let topic = received.0;
            let mut topic_error = Topic::Errors.as_str().to_string();
            topic_error.push_str("/");
            topic_error.push_str(&pub_key);
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
                    match self.handle_message(msg, &topic).await {
                        Ok(Some(res)) => {
                            // Do something
                            let response = res.0;
                            let topic_response = res.1;
                            if topic_response == "terminate" {
                                *keep_running.lock().await = false;
                                continue;
                            }
                            let _ = response.clone();
                            {
                                let responder = responder.lock().await;
                                let _ = responder
                                    .send_message(&topic_response, response.clone())
                                    .await;
                            }
                        }
                        Ok(None) => {}
                        Err(errormessage) => {
                            //println!("errormessage {:?}", errormessage);
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id,
                            };
                            let _ = response.to_string();
                            {
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

        let mut this_pub_key = None;
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

    pub async fn get_pub_key_from_session_id(&self, session_id: &str) -> Result<String, String> {
        if let Some(session_data) = self.sessions.lock().await.get(session_id) {
            let pub_key = session_data.pub_key.clone();
            Ok(pub_key)
        } else {
            Err("Nope".to_string())
        }
    }

    #[async_recursion]
    pub async fn handle_message(
        &mut self,
        message: Message,
        topic: &str,
    ) -> Result<Option<(Message, String)>, SessionErrorMsg> {
        let mut topic_response = topic.to_string();
        let mut response = Message::new_chat("Hello World".to_string());
        response.session_id = message.session_id.clone();
        let session_id = message.session_id.clone();
        let _msg_raw = message.to_string();

        match message.message {
            Internal(msg) => {
                if topic == Topic::Internal.as_str() {
                    if message.session_id == "internal" && msg.message == "terminate" {
                        self.call_callbacks_terminate().await;
                        *self.running.lock().await = false;
                        return Ok(None);
                    }

                    let session_id = message.session_id.clone();
                    let message = Message {
                        message: MessageData::Chat(ChatMsg {
                            message: msg.message.to_string(),
                        }),
                        session_id: session_id.clone(),
                    };
                    let msg_enc = self.encrypt_msg(&session_id, &message).await;
                    if msg_enc.is_ok() {
                        let msg_enc = msg_enc.unwrap();

                        let message = Message {
                            message: MessageData::Encrypted(msg_enc),
                            session_id: session_id.clone(),
                        };
                        topic_response = msg.topic;

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
            DiscoveryReply(_msg) => {
                let pub_key = _msg.pub_key.clone();

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

                let mut this_fingerprint = None;
                {
                    this_fingerprint =
                        Some(self.host_encro.lock().await.get_public_key_fingerprint());
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
            Heartbeat(_msg) => {
                if let Some(session_data) = self.sessions.lock().await.get_mut(&session_id) {
                    session_data.last_active = SystemTime::now();
                }
                Ok(None)
            }
            Discovery(_msg) => {
                let pub_key = _msg.pub_key.clone();

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

                let mut this_fingerprint = None;
                {
                    this_fingerprint =
                        Some(self.host_encro.lock().await.get_public_key_fingerprint());
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

                response = Message::new_discovery_reply(
                    self.host_encro.lock().await.get_public_key_as_base64(),
                );
                response.session_id = message.session_id.clone();
                Ok(Some((response, topic_response)))
            }
            Init(msg) => {
                {
                    if self.host_encro.lock().await.get_public_key_as_base64() == msg.pub_key {
                        return Ok(None);
                    }
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
                        let initialize_this = self.call_callbacks_init_incoming(&pub_key).await;
                        let this_pub_key = self.host_encro.lock().await.get_public_key_as_base64();
                        if initialize_this {
                            {
                                let sym_cipher = ChaCha20Poly1305EnDeCrypt::new();
                                let sym_cipher_key = sym_cipher.get_public_key_as_base64();
                                let sym_cipher_key_encrypted =
                                    match pub_encro.encrypt(&sym_cipher_key) {
                                        Ok(res) => res,
                                        Err(_) => {
                                            return Err(SessionErrorMsg {
                                                code: SessionErrorCodes::Encryption as u32,
                                                message: "Failed to encrypt session key".to_owned(),
                                            });
                                        }
                                    };
                                let pk_1 = pub_encro.get_public_key_fingerprint();
                                let pk_2 =
                                    self.host_encro.lock().await.get_public_key_fingerprint();

                                let s = pk_1.clone() + &pk_2;
                                let key = sha256sum(&s);
                                let pub_key = pub_encro.get_public_key_as_base64();

                                let challenge_sig =
                                    match self.host_encro.lock().await.sign(&challenge) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            return Err(SessionErrorMsg {
                                                code: SessionErrorCodes::Encryption as u32,
                                                message: "Failed to create signature of challenge"
                                                    .to_owned(),
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
                                };
                                let mut msg = Message::new_init_ok(
                                    sym_cipher_key_encrypted.clone(),
                                    this_pub_key.clone(),
                                    pub_encro.get_public_key_as_base64(),
                                    challenge_sig,
                                );
                                msg.session_id = key.clone();

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
                            //self.chat(key.clone(), &pk_1, false).await;
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
                let session_id = session_id.clone();
                let challenge_sig = msg.challenge_sig.clone();
                let sym_key_encrypted = msg.sym_key_encrypted.clone();
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
                    let cert = cert.unwrap();
                    let other_key_fingerprint = cert.fingerprint().to_string();

                    let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
                    let key = session_id;
                    let session_data = SessionData {
                        id: key.clone(),
                        last_active: SystemTime::now(),
                        state: SessionState::Active,
                        messages: Vec::new(),
                        sym_encro: cipher,
                        pub_key: add_session_pub_key.clone(),
                    };

                    let new_session_data = session_data.clone();
                    let new_session_id = session_data.id.clone();

                    {
                        let mut sessions = self.sessions.lock().await;
                        sessions.insert(new_session_id.clone(), new_session_data);
                    }

                    self.call_callbacks_init_accepted(&add_session_pub_key.clone())
                        .await;

                    self.chat(
                        new_session_id.clone(),
                        &other_key_fingerprint,
                        false,
                        add_session_pub_key.clone(),
                    )
                    .await;
                }
                Ok(None)
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
                    Ok(None)
                } else {
                    Err(SessionErrorMsg {
                        code: SessionErrorCodes::InvalidPublicKey as u32,
                        message: "Invalid public key".to_owned(),
                    })
                }
            }
            Encrypted(msg) => {
                let mut dec_msg = None;
                {
                    let sm = &self.sessions.lock().await;
                    let cipher = match sm.get(&message.session_id) {
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
                    self.handle_message(dec_msg, topic).await
                } else {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::Encryption as u32,
                        message: "Failed to decrypt message".to_owned(),
                    });
                }
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
}
