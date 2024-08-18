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
    pub rx_local_callbacks: Arc<Mutex<Vec<Box<dyn Fn(&str, &str) + Send>>>>,

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
            rx_local_callbacks: Arc::new(Mutex::new(Vec::new())),
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
    pub async fn register_rx_local_callback(&self, callback: Box<dyn Fn(&str, &str) + Send>) {
        let mut callbacks = self.rx_local_callbacks.lock().await;
        callbacks.push(callback);
    }

    // Call all registered callbacks
    async fn call_rx_local_callbacks(&self, arg1: &str, arg2: &str) {
        let callbacks = self.rx_local_callbacks.lock().await;
        for callback in callbacks.iter() {
            callback(arg1, arg2);
        }
    }

    pub async fn initialize_session_zenoh(&self, pub_key: String) -> Result<String, String> {
        let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
        let cert = read_from_vec(&pub_key_dec);
        if cert.is_err() {
            return Err("Failed to parse public key".to_owned());
        }
        let cert = cert.unwrap();
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

        let await_response_interval = Duration::from_secs(5);

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
                        let mut hm = self.sessions.lock().await;
                        hm.insert(key.clone(), session_data);
                        return Ok(key);
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

            let h = tokio::spawn(async move {
                let zenoh_config = Config::from_file(zc).unwrap();
                let zenoh_session =
                    Arc::new(Mutex::new(zenoh::open(zenoh_config).res().await.unwrap()));
                let handler = ZenohHandler::new(zenoh_session);
                let mut keep_alive = true;
                while keep_alive {
                    let result = handler.read_messages(&topic, &tx_clone).await;
                    keep_alive = result.is_ok();
                }
                println!("No longer serving topic: {}", &t);
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
                    match self.handle_message(msg, &topic).await {
                        Ok(res) => {
                            // Do something
                            let response = res.0;
                            let topic = res.1;
                            responder.send_message(&topic, response).await;
                        }
                        Err(errormessage) => {
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id: session_id,
                            };
                            let rs = response.to_string();
                            responder.send_message(&topic_response, response).await;
                            println!("(NOT OK) responded on topic {} - {}", topic_response, rs);
                        }
                    }
                }
                Err(_) => {}
            };
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

        // Then, if necessary, spawn a new task without capturing self
        let h = tokio::spawn(async move {
            loop {
                print!(">> ");
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read line");
                let input = input.trim();
                let topic = Topic::Internal.as_str();
                let msg = Message::new_internal(
                    session_id.to_string(),
                    input.to_string(),
                    topic_out.to_string(),
                );
                if let Err(e) = tx_clone
                    .send((topic.to_string(), msg.serialize().unwrap()))
                    .await
                {
                    eprintln!("Failed to send message: {}", e);
                }
            }
        });

        if blocking {
            h.await.unwrap();
        }
    }

    pub async fn serve_with_chat(&mut self) {
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
                            match m.clone().message {
                                InitOk(m) => {
                                    let pk = m.orig_pub_key;
                                    println!("starting chatting {}", &pk);
                                    // Start chatting
                                    let pub_key_dec =
                                        base64::decode(&pk).expect("Failed to decode pub_key");
                                    let discovered_cert = read_from_vec(&pub_key_dec)
                                        .expect("Got invalid certificate from discovery");
                                    let discovered_pub_key_fingerprint =
                                        discovered_cert.fingerprint().to_string();
                                    self.chat(
                                        response.session_id.clone(),
                                        &discovered_pub_key_fingerprint,
                                        false,
                                    )
                                    .await;
                                }
                                _ => {}
                            }
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
                    println!("Got message: {}", topic);
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
                            println!("(NOT OK) responded on topic {} - {}", topic_response, rs);
                            exit(1);
                        }
                    }
                }
                Err(_) => {}
            };
            {
                let mut hm = self.sessions.lock().await;
                if hm.len() > 0 {
                    println!("Successfully created a session!");
                    thread::spawn(|| {
                        // Sleep for 3 seconds
                        thread::sleep(Duration::from_secs(3));
                        // Exit the program with code 0
                        exit(0);
                    });
                } else {
                    println!("-- zero sessions yet.. {}", msg_count);
                }
            }
        }
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
        let msg_raw = message.to_string();

        match message.message {
            Internal(msg) => {
                if topic == Topic::Internal.as_str() {
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
                println!("Discovery message received");
                response =
                    Message::new_discovery(self.host_encro.lock().await.get_public_key_as_base64());
                response.session_id = message.session_id.clone();
                Ok((response, topic_response))
            }
            Init(msg) => {
                println!("Init message received");
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
                        let mut s = pk_1 + &pk_2;
                        let key = sha256sum(&s);
                        let session_data = SessionData {
                            id: key.clone(),
                            last_active: SystemTime::now(),
                            state: SessionState::Initializing,
                            pub_key: pub_encro.get_public_key_as_base64(),
                            messages: Vec::new(),
                            sym_encro: sym_cipher,
                        };
                        let mut hm = self.sessions.lock().await;
                        hm.insert(key.clone(), session_data);
                        println!("Session created with id {}", &key);
                        response.message = MessageData::InitOk(InitOkMsg {
                            sym_key: sym_cipher_key_encrypted,
                            orig_pub_key: pub_encro.get_public_key_as_base64(),
                        });
                        response.session_id = key;
                        Ok((response, topic_response))
                    }
                    Err(_) => {
                        println!("Invalid public key");
                        Err(SessionErrorMsg {
                            code: SessionErrorCodes::InvalidPublicKey as u32,
                            message: "Invalid public key".to_owned(),
                        })
                    }
                }
            }
            Close(_msg) => {
                println!("Close message received");
                Ok((response, topic_response))
            }
            Ping(_msg) => {
                println!("Ping message received");
                Ok((response, topic_response))
            }
            Chat(msg) => {
                self.call_rx_local_callbacks(&topic, &msg.message).await;
                Ok((response, topic_response))
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
