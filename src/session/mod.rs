use std::collections::HashMap;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{mpsc, Mutex};

pub mod crypto;
pub mod messages;
pub mod middleware;
pub mod protocol;

use protocol::*;

use crypto::{
    sha256sum, ChaCha20Poly1305EnDeCrypt, Cryptical, CrypticalDecrypt, CrypticalEncrypt,
    PGPEnCryptOwned, PGPEnDeCrypt,
};

use messages::MessageData::{Chat, Close, Discovery, Encrypted, Init, InitOk, Ping};
use messages::MessagingError::*;
use messages::SessionMessage as Message;
use messages::{
    ChatMsg, EncryptedMsg, InitMsg, InitOkMsg, MessageData, MessageListener, Messageble,
    MessagebleTopicAsync, MessagebleTopicAsyncPublishReads, MessagebleTopicAsyncReadTimeout,
    MessagingError, SessionErrorCodes, SessionErrorMsg,
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
    pub host_encro: HostCrypto,
}

impl<'a> Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt<'a>> {
    pub fn new(host_encro: PGPEnDeCrypt<'a>) -> Self {
        Session {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            host_encro,
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
        if session_data.state != SessionState::Active {
            return Err(InvalidSession);
        }
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

    pub async fn initialize_session_zenoh(&self, pub_key: String) -> Result<String, String> {
        let pub_key_dec = base64::decode(&pub_key).expect("Failed to decode pub_key");
        let cert = read_from_vec(&pub_key_dec);
        if cert.is_err() {
            return Err("Failed to parse public key".to_owned());
        }
        let cert = cert.unwrap();
        let message = Message {
            message: MessageData::Init(InitMsg {
                pub_key: self.host_encro.get_public_key_as_base64(),
            }),
            session_id: "".to_string(),
        };
        let mut topic = Topic::Initialize.as_str().to_string();
        topic.push_str("/");
        topic.push_str(&cert.fingerprint().to_string());

        let zenoh_session = Arc::new(Mutex::new(zenoh::open(config::peer()).res().await.unwrap()));
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
                        let sym_key = match self.host_encro.decrypt(&sym_key_encrypted) {
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
        let pub_key = self.host_encro.get_public_key_as_base64();
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
                    let sym_key = match self.host_encro.decrypt(&sym_key_encrypted) {
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

        println!("Topics to subscribe to {}", topics.len());
        for topic in topics {
            let tx_clone = tx.clone();
            let t = topic.clone();

            println!("Subscribing to topic: {}", &t);
            let h = tokio::spawn(async move {
                let zenoh_session =
                    Arc::new(Mutex::new(zenoh::open(config::peer()).res().await.unwrap()));
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
        let pub_key = self.host_encro.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        // the initialization topic
        let mut init_topic = Topic::Initialize.as_str().to_owned();
        init_topic.push_str("/");
        init_topic.push_str(&pub_key);
        // the message topic
        let mut message_topic = Topic::messaging_topic_in(&pub_key);

        topics_to_subscribe.push(init_topic);
        topics_to_subscribe.push(message_topic);
        topics_to_subscribe.push(Topic::Discover.as_str().to_owned());

        let (tx, mut rx) = mpsc::channel(100);
        self.serve_topics(topics_to_subscribe, &tx, false).await;

        let zenoh_session_responder =
            Arc::new(Mutex::new(zenoh::open(config::peer()).res().await.unwrap()));
        let responder = ZenohHandler::new(zenoh_session_responder);

        while let Some(received) = rx.recv().await {
            let topic = received.0;
            let mut topic_response = topic.clone();
            topic_response.push_str(Topic::reply_suffix());
            let msg = match Message::deserialize(&received.1) {
                Ok(msg) => {
                    println!("Got message: {}", topic);
                    let session_id = msg.session_id.clone();
                    match self.handle_message(msg).await {
                        Ok(response) => {
                            // Do something
                            responder.send_message(&topic_response, response).await;
                            println!("(OK) responded on topic {}", topic_response);
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

    pub async fn serve_testing(&mut self) {
        let pub_key = self.host_encro.get_public_key_fingerprint();
        let mut topics_to_subscribe = Vec::new();

        // the initialization topic
        let mut init_topic = Topic::Initialize.as_str().to_owned();
        init_topic.push_str("/");
        init_topic.push_str(&pub_key);
        // the message topic
        let mut message_topic = Topic::messaging_topic_in(&pub_key);

        topics_to_subscribe.push(init_topic);
        topics_to_subscribe.push(message_topic);
        topics_to_subscribe.push(Topic::Discover.as_str().to_owned());

        let (tx, mut rx) = mpsc::channel(100);
        self.serve_topics(topics_to_subscribe, &tx, false).await;

        let zenoh_session_responder =
            Arc::new(Mutex::new(zenoh::open(config::peer()).res().await.unwrap()));
        let responder = ZenohHandler::new(zenoh_session_responder);

        let mut msg_count = 0;

        while let Some(received) = rx.recv().await {
            msg_count += 1;
            let topic = received.0;
            let mut topic_response = topic.clone();
            topic_response.push_str(Topic::reply_suffix());

            let msg = match Message::deserialize(&received.1) {
                Ok(msg) => {
                    println!("Got message: {}", topic);
                    let session_id = msg.session_id.clone();
                    match self.handle_message(msg).await {
                        Ok(response) => {
                            // Do something
                            responder.send_message(&topic_response, response).await;
                            println!("(OK) responded on topic {}", topic_response);
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

    pub async fn serve_old<T: MessageListener + Messageble>(&mut self, server: &T) {
        loop {
            match server.listen() {
                Ok(message) => {
                    let session_id = message.session_id.clone();
                    match self.handle_message(message).await {
                        Ok(response) => {
                            // Do something
                            match server.send_message(response) {
                                Ok(_) => {}
                                Err(_) => {}
                            }
                        }
                        Err(errormessage) => {
                            let response = Message {
                                message: MessageData::SessionError(errormessage),
                                session_id: session_id,
                            };
                            match server.send_message(response) {
                                Ok(_) => {}
                                Err(_) => {}
                            }
                        }
                    }
                }
                Err(_) => {}
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
    pub async fn handle_message(&mut self, message: Message) -> Result<Message, SessionErrorMsg> {
        let mut response = Message::new_init_ok("World".to_string());
        response.session_id = message.session_id.clone();
        let msg_raw = message.to_string();
        match message.message {
            Discovery(_msg) => {
                println!("Discovery message received");
                response = Message::new_discovery(self.host_encro.get_public_key_as_base64());
                response.session_id = message.session_id.clone();
                Ok(response)
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
                        let pk_2 = self.host_encro.get_public_key_fingerprint();
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
                        });
                        response.session_id = key;
                        Ok(response)
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
                Ok(response)
            }
            Ping(_msg) => {
                println!("Ping message received");
                Ok(response)
            }
            Chat(msg) => {
                println!("- {}", msg.message);
                Ok(response)
            }
            Encrypted(msg) => {
                println!(
                    "Encrypted message received: id {}, raw: {}",
                    message.session_id, msg_raw
                );
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
                    self.handle_message(dec_msg).await
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
