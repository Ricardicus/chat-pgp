use std::collections::HashMap;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use std::env;
use std::io::{self, Write};

pub mod crypto;
pub mod messages;
pub mod middleware;
pub mod protocol;

use protocol::*;

use crypto::{
    sha256sum, ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalDecrypt, CrypticalEncrypt,
    PGPEnCryptOwned, PGPEnDeCrypt,
};

use messages::MessageData::{Chat, Close, Discovery, Encrypted, Init, InitOk, Internal, Ping};
use messages::MessagingError::*;
use messages::SessionMessage as Message;
use messages::{
    ChatMsg, EncryptedMsg, InitMsg, InitOkMsg, InternalMsg, MessageData, MessageListener,
    Messageble, MessagebleTopicAsync, MessagebleTopicAsyncPublishReads,
    MessagebleTopicAsyncReadTimeout, MessagingError, SessionErrorCodes, SessionErrorMsg,
};
use middleware::ZenohHandler;

use crate::pgp::pgp::read_from_vec;

use futures::prelude::*;
use zenoh::prelude::r#async::*;

use async_recursion::async_recursion;

#[derive(PartialEq)]
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
    pub host_encro: Arc<Mutex<HostCrypto>>,
    pub tx: mpsc::Sender<(String, String)>,
    pub rx: mpsc::Receiver<(String, String)>,
    pub callbacks_chat: Arc<Mutex<Vec<Box<dyn Fn(&str, &str) + Send>>>>,
    pub callbacks_discovered: Arc<Mutex<Vec<Box<dyn Fn(&str) -> bool + Send>>>>,
    pub callbacks_initialized: Arc<Mutex<Vec<Box<dyn Fn(&str) -> bool + Send>>>>,
    pub callbacks_terminate: Arc<Mutex<Vec<Box<dyn Fn() + Send>>>>,
    pub callbacks_chat_input:
        Arc<Mutex<Vec<Box<dyn Fn(&str, &str, &str) -> (String, String) + Send + Sync>>>>,

    pub middleware_config: String,
}

impl<'a> Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt<'a>> {
    pub fn new(host_encro: PGPEnDeCrypt<'a>, middleware_config: String) -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        Session {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            host_encro: Arc::new(Mutex::new(host_encro)),
            tx,
            rx,
            callbacks_chat: Arc::new(Mutex::new(Vec::new())),
            callbacks_discovered: Arc::new(Mutex::new(Vec::new())),
            callbacks_initialized: Arc::new(Mutex::new(Vec::new())),
            callbacks_terminate: Arc::new(Mutex::new(Vec::new())),
            callbacks_chat_input: Arc::new(Mutex::new(Vec::new())),
            middleware_config,
        }
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

    pub async fn session_send_msg<T: Messageble>(
        &mut self,
        session_id: &str,
        msg: Message,
        msgable: &T,
    ) -> Result<(), MessagingError> {
        match self.encrypt_msg(session_id, &msg).await {
            Ok(msg) => {
                match msgable.send_message(Message {
                    message: MessageData::Encrypted(msg),
                    session_id: session_id.to_string(),
                }) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Err(err) => Err(err),
        }
    }

    // Register a new callback
    pub async fn register_callback_chat(&self, callback: Box<dyn Fn(&str, &str) + Send>) {
        let mut callbacks = self.callbacks_chat.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_discovered(&self, callback: Box<dyn Fn(&str) -> bool + Send>) {
        let mut callbacks = self.callbacks_discovered.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_initialized(&self, callback: Box<dyn Fn(&str) -> bool + Send>) {
        let mut callbacks = self.callbacks_initialized.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_terminate(&self, callback: Box<dyn Fn() + Send>) {
        let mut callbacks = self.callbacks_terminate.lock().await;
        callbacks.push(callback);
    }
    pub async fn register_callback_chat_input(
        &self,
        callback: Box<dyn Fn(&str, &str, &str) -> (String, String) + Send + Sync>,
    ) {
        let mut callbacks = self.callbacks_chat_input.lock().await;
        callbacks.push(callback);
    }

    async fn call_callbacks_chat(&self, arg1: &str, arg2: &str) {
        let callbacks = self.callbacks_chat.lock().await;
        for callback in callbacks.iter() {
            callback(arg1, arg2);
        }
    }
    async fn call_callbacks_terminate(&self) {
        let callbacks = self.callbacks_terminate.lock().await;
        for callback in callbacks.iter() {
            callback();
        }
    }
    async fn call_callbacks_initialized(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_initialized.lock().await;
        for callback in callbacks.iter() {
            if !callback(arg1) {
                return false;
            }
        }
        true
    }
    async fn call_callbacks_discovered(&self, arg1: &str) -> bool {
        let callbacks = self.callbacks_discovered.lock().await;
        for callback in callbacks.iter() {
            if !callback(arg1) {
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
        let message = Message {
            message: MessageData::Init(InitMsg {
                pub_key: self.host_encro.lock().await.get_public_key_as_base64(),
            }),
            session_id: "".to_string(),
        };
        let mut topic = Topic::Initialize.as_str().to_string();
        topic.push_str("/");
        topic.push_str(&cert.fingerprint().to_string());
        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session = Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
        let handler = ZenohHandler::new(zenoh_session);

        let await_response_interval = Duration::from_secs(60);

        let mut topic_reply = topic.clone();
        topic_reply.push_str(Topic::reply_suffix());

        handler.send_message(&topic, message).await;
        match handler
            .read_message_timeout(&topic_reply, await_response_interval)
            .await
        {
            Ok(msg) => {
                let session_id = msg.session_id;
                match msg.message {
                    InitOk(msg) => {
                        let sym_key_encrypted = msg.sym_key;
                        let sym_key = match self.host_encro.lock().await.decrypt(&sym_key_encrypted)
                        {
                            Ok(res) => res,
                            Err(_) => {
                                return Err("Failed to decrypt session key".to_owned());
                            }
                        };
                        let initialize_this = self.call_callbacks_initialized(&pub_key).await;
                        if initialize_this {
                            let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
                            let key = session_id;
                            let session_data = SessionData {
                                id: key.clone(),
                                last_active: SystemTime::now(),
                                state: SessionState::Active,
                                messages: Vec::new(),
                                sym_encro: cipher,
                                pub_key: pub_key.clone(),
                            };
                            {
                                let mut hm = self.sessions.lock().await;
                                hm.insert(key.clone(), session_data);
                            }
                            self.chat(key.clone(), &other_key_fingerprint, false).await;
                            return Ok(key);
                        } else {
                            return Err("Session not initialized, not accepted".to_owned());
                        }
                    }
                    _ => {
                        return Err("Failed to initialize session".to_owned());
                    }
                }
            }
            Err(_) => {
                return Err("No response from session".to_string());
            }
        }
    }

    pub async fn initialize_session<T: MessageListener + Messageble>(
        &mut self,
        client: &T,
    ) -> Result<String, String> {
        let pub_key = self.host_encro.lock().await.get_public_key_as_base64();
        let message = Message {
            message: MessageData::Init(InitMsg {
                pub_key: pub_key.clone(),
            }),
            session_id: "".to_string(),
        };
        match client.send_message(message) {
            Ok(_) => {}
            Err(_) => {
                return Err("Failed to send message".to_owned());
            }
        }

        match client.listen() {
            Ok(message) => match message.message {
                InitOk(msg) => {
                    let sym_key_encrypted = msg.sym_key;
                    let sym_key = match self.host_encro.lock().await.decrypt(&sym_key_encrypted) {
                        Ok(res) => res,
                        Err(_) => {
                            return Err("Failed to decrypt session key".to_owned());
                        }
                    };
                    let cipher = ChaCha20Poly1305EnDeCrypt::new_from_str(&sym_key);
                    let key = message.session_id.clone();
                    let session_data = SessionData {
                        id: key.clone(),
                        last_active: SystemTime::now(),
                        state: SessionState::Active,
                        messages: Vec::new(),
                        sym_encro: cipher,
                        pub_key: pub_key.clone(),
                    };
                    let mut hm = self.sessions.lock().await;
                    hm.insert(key.clone(), session_data);
                    return Ok(key);
                }
                _ => {
                    return Err("Failed to initialize session".to_owned());
                }
            },
            Err(_) => {
                return Err("Failed to initialize session".to_owned());
            }
        };
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
            let t = topic.clone();
            let zc = self.middleware_config.clone();

            let terminate_callbacks = self.callbacks_terminate.clone();
            let h = tokio::spawn(async move {
                let zenoh_config = Config::from_file(zc).unwrap();
                let zenoh_session = zenoh::open(zenoh_config.clone()).res().await;

                if zenoh_session.is_err() {
                    let callbacks = terminate_callbacks.lock().await;
                    for callback in callbacks.iter() {
                        callback();
                    }
                    return false;
                }
                let zenoh_session = Arc::new(Mutex::new(zenoh_session.unwrap()));
                let handler = ZenohHandler::new(zenoh_session);
                let mut keep_alive = true;
                while keep_alive {
                    let result = handler.read_messages(&topic, &tx_clone).await;
                    keep_alive = result.is_ok();
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

    pub async fn chat(&mut self, session_id: String, other_key_fingerprint: &str, blocking: bool) {
        let pub_key_fingerprint = self.host_encro.lock().await.get_public_key_fingerprint();
        let topic_in = Topic::messaging_topic_in(pub_key_fingerprint.as_ref());
        let topic_out = Topic::messaging_topic_in(&other_key_fingerprint);

        let mut topics: Vec<String> = Vec::new();
        topics.push(topic_in);

        let tx_clone = self.tx.clone();
        self.serve_topics(topics, &tx_clone, false).await;

        let other_key_fingerprint: String = other_key_fingerprint.to_string();

        let callbacks = self.callbacks_chat_input.clone();
        let h = tokio::spawn(async move {
            loop {
                let callbacks = callbacks.lock().await;
                for callback in callbacks.iter() {
                    let (topic, msg) = callback(&other_key_fingerprint, &session_id, &topic_out);
                    if let Err(e) = tx_clone.send((topic, msg)).await {}
                }
            }
        });

        if blocking {
            h.await.unwrap();
        }
    }

    pub async fn serve(&mut self) {
        let pub_key = self.host_encro.lock().await.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        // the initialization topic
        let mut init_topic = Topic::Initialize.as_str().to_owned();
        init_topic.push_str("/");
        init_topic.push_str(&pub_key);

        topics_to_subscribe.push(init_topic);
        topics_to_subscribe.push(Topic::Discover.as_str().to_owned());

        let tx_clone = self.tx.clone();
        self.serve_topics(topics_to_subscribe, &tx_clone, false)
            .await;
        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session_responder =
            Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
        let responder = ZenohHandler::new(zenoh_session_responder);

        while let Some(received) = self.rx.recv().await {
            let topic = received.0;
            let mut topic_response = topic.clone();
            topic_response.push_str(Topic::reply_suffix());
            let msg = match Message::deserialize(&received.1) {
                Ok(msg) => {
                    let session_id = msg.session_id.clone();
                    let msg_clone = msg.clone();
                    match self.handle_message(msg, &topic).await {
                        Ok(res) => {
                            // Do something
                            let response = res.0;
                            let topic_response = res.1;
                            let m = response.clone();
                            responder
                                .send_message(&topic_response, response.clone())
                                .await;
                        }
                        Err(errormessage) => {
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id: session_id,
                            };
                            let rs = response.to_string();
                            responder.send_message(&topic_response, response).await;
                        }
                    }
                }
                Err(_) => {}
            };
        }
    }

    pub async fn serve_testing(&mut self) {
        let pub_key = self.host_encro.lock().await.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        // the initialization topic
        let mut init_topic = Topic::Initialize.as_str().to_owned();
        init_topic.push_str("/");
        init_topic.push_str(&pub_key);

        topics_to_subscribe.push(init_topic);
        topics_to_subscribe.push(Topic::Discover.as_str().to_owned());

        let tx_clone = self.tx.clone();
        self.serve_topics(topics_to_subscribe, &tx_clone, false)
            .await;
        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session_responder =
            Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
        let responder = ZenohHandler::new(zenoh_session_responder);

        let mut msg_count = 0;

        while let Some(received) = self.rx.recv().await {
            msg_count += 1;
            let topic = received.0;
            let mut topic_response = topic.clone();
            topic_response.push_str(Topic::reply_suffix());

            let msg = match Message::deserialize(&received.1) {
                Ok(msg) => {
                    let session_id = msg.session_id.clone();
                    match self.handle_message(msg, &topic).await {
                        Ok(res) => {
                            // Do something
                            let response = res.0;
                            let topic_response = res.1;
                            responder.send_message(&topic_response, response).await;
                        }
                        Err(errormessage) => {
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id: session_id,
                            };
                            let rs = response.to_string();
                            responder.send_message(&topic_response, response).await;
                            exit(1);
                        }
                    }
                }
                Err(_) => {}
            };
            {
                let mut hm = self.sessions.lock().await;
                if hm.len() > 0 {
                    thread::spawn(|| {
                        // Sleep for 3 seconds
                        thread::sleep(Duration::from_secs(3));
                        // Exit the program with code 0
                        exit(0);
                    });
                } else {
                }
            }
        }
    }

    pub async fn discover(&mut self) -> Vec<String> {
        let discover_topic = Topic::Discover.as_str();
        let mut discover_topic_reply = discover_topic.to_string();
        discover_topic_reply.push_str(Topic::reply_suffix());
        let timeout_discovery = Duration::from_secs(5);
        let mut pub_keys = Vec::new();

        let zc = self.middleware_config.clone();
        let zenoh_config = Config::from_file(zc).unwrap();
        let zenoh_session = Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
        let handler = ZenohHandler::new(zenoh_session);

        let mut this_pub_key = None;
        {
            this_pub_key = Some(self.host_encro.lock().await.get_public_key_as_base64());
        }
        let msg = Message::new_discovery(this_pub_key.clone().unwrap());
        match self
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
                for msg in msgs {
                    match msg.message {
                        Discovery(disc_msg) => {
                            let pub_key = disc_msg.pub_key.clone();
                            if !pub_keys.contains(&pub_key) {
                                let pub_key_dec =
                                    base64::decode(&pub_key).expect("Failed to decode pub_key");
                                let discovered_cert = read_from_vec(&pub_key_dec)
                                    .expect("Got invalid certificate from discovery");
                                let discovered_pub_key_fingerprint =
                                    discovered_cert.fingerprint().to_string();
                                let not_ignore = self.call_callbacks_discovered(&pub_key).await;
                                if not_ignore {
                                    pub_keys.push(disc_msg.pub_key);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {}
        };
        pub_keys
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
            Err(error) => return Err(MessagingError::UnreachableHost),
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
            Err(error) => return Err(MessagingError::UnreachableHost),
        };
        gateway.read_messages_timeout(topic_rx, timeout).await
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
    ) -> Result<(Message, String), SessionErrorMsg> {
        let mut topic_response = topic.to_string();
        topic_response.push_str(Topic::reply_suffix());
        let mut response = Message::new_chat("Hello World".to_string());
        response.session_id = message.session_id.clone();
        let session_id = message.session_id.clone();
        let msg_raw = message.to_string();

        match message.message {
            Internal(msg) => {
                if topic == Topic::Internal.as_str() {
                    if message.session_id == "internal" && msg.message == "terminate" {
                        self.call_callbacks_terminate().await;
                        exit(0);
                    }

                    let session_id = message.session_id.clone();
                    let message = Message {
                        message: MessageData::Chat(ChatMsg {
                            message: msg.message.to_string(),
                        }),
                        session_id: session_id.clone(),
                    };
                    let msg_enc = self.encrypt_msg(&session_id, &message).await.unwrap();
                    let message = Message {
                        message: MessageData::Encrypted(msg_enc),
                        session_id: session_id.clone(),
                    };
                    topic_response = msg.topic;

                    let pk = self.host_encro.lock().await.get_public_key_as_base64();
                    self.call_callbacks_chat(&pk, &msg.message).await;

                    // Send this message
                    return Ok((message, topic_response));
                } else {
                    return Err(SessionErrorMsg {
                        code: SessionErrorCodes::Protocol as u32,
                        message: "Invalid internal message topic".to_owned(),
                    });
                }
            }
            Discovery(_msg) => {
                let pk = _msg.pub_key.clone();
                response =
                    Message::new_discovery(self.host_encro.lock().await.get_public_key_as_base64());
                response.session_id = message.session_id.clone();
                Ok((response, topic_response))
            }
            Init(msg) => {
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
                        let pk_1 = pub_encro.get_public_key_fingerprint();
                        let pk_2 = self.host_encro.lock().await.get_public_key_fingerprint();
                        let s = pk_1.clone() + &pk_2;
                        let key = sha256sum(&s);
                        let pub_key = pub_encro.get_public_key_as_base64();
                        let session_data = SessionData {
                            id: key.clone(),
                            last_active: SystemTime::now(),
                            state: SessionState::Initializing,
                            pub_key: pub_key.clone(),
                            messages: Vec::new(),
                            sym_encro: sym_cipher,
                        };
                        let initialize_this = self.call_callbacks_initialized(&pub_key).await;

                        if initialize_this {
                            {
                                let mut hm = self.sessions.lock().await;
                                hm.insert(key.clone(), session_data);
                            }

                            response.message = MessageData::InitOk(InitOkMsg {
                                sym_key: sym_cipher_key_encrypted,
                                orig_pub_key: pub_encro.get_public_key_as_base64(),
                            });
                            response.session_id = key.clone();
                            self.chat(key.clone(), &pk_1, false).await;
                            Ok((response, topic_response))
                        } else {
                            Err(SessionErrorMsg {
                                code: SessionErrorCodes::NotAccepted as u32,
                                message: "Session initialization not accepted".to_owned(),
                            })
                        }
                    }
                    Err(_) => Err(SessionErrorMsg {
                        code: SessionErrorCodes::InvalidPublicKey as u32,
                        message: "Invalid public key".to_owned(),
                    }),
                }
            }
            Close(_msg) => Ok((response, topic_response)),
            Ping(_msg) => Ok((response, topic_response)),
            Chat(msg) => {
                if let Some(session_data) = self.sessions.lock().await.get(&session_id) {
                    let pub_key = session_data.pub_key.clone();
                    self.call_callbacks_chat(&pub_key, &msg.message).await;
                    Ok((response, topic_response))
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
}
