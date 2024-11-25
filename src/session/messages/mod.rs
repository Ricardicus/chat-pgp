use crate::session::protocol::challenge_len;
use crate::util::{generate_random_string, get_current_datetime};
use serde::{Deserialize, Serialize};
use serde_cbor;
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum EncryptionType {
    Assymetric,
    Symmetric,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitMsg {
    pub pub_key: String,
    pub signature: String,
    pub challenge: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitOkMsg {
    pub sym_key_encrypted: String,
    pub pub_key: String,
    pub orig_pub_key: String,
    pub challenge_sig: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitAwaitMsg {
    pub pub_key: String,
    pub orig_pub_key: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitDeclineMsg {
    pub pub_key: String,
    pub message: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPassMsg {
    pub sym_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CloseMsg {
    pub session_id: String,
    pub pub_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMsg {
    pub message: String,
    pub sender_userid: String,
    pub sender_fingerprint: String,
    pub date_time: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReplayMsg {
    pub key_id: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReplayResponseMsg {
    pub session_id: String,
    pub messages: Vec<SessionMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CloseOkMsg {
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HeartbeatMsg {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingMsg {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PongMsg {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedMsg {
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmailMsg {
    pub session_id: String,
    pub message: EncryptedMsg,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiscoveryMsg {
    pub pub_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiscoveryReplyMsg {
    pub pub_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InternalMsg {
    pub message: String,
    pub topic: String,
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SessionErrorCodes {
    Serialization = 1,
    InvalidMessage = 2,
    InvalidPublicKey = 3,
    Encryption = 4,
    Timeout = 5,
    Protocol = 6,
    NotAccepted = 7,
    InvalidSignature = 8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionErrorMsg {
    pub code: u32,
    pub message: String,
}

// Define an enum to encapsulate different message data types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MessageData {
    Init(InitMsg),
    InitOk(InitOkMsg),
    InitAwait(InitAwaitMsg),
    InitDecline(InitDeclineMsg),
    Close(CloseMsg),
    CloseOk(CloseOkMsg),
    Chat(ChatMsg),
    Ping(PingMsg),
    Pong(PongMsg),
    Encrypted(EncryptedMsg),
    SessionError(SessionErrorMsg),
    KeyPass(KeyPassMsg),
    Discovery(DiscoveryMsg),
    DiscoveryReply(DiscoveryReplyMsg),
    Internal(InternalMsg),
    Heartbeat(HeartbeatMsg),
    Replay(ReplayMsg),
    ReplayResponse(ReplayResponseMsg),
    Email(EmailMsg),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessagingError {
    InvalidAddress,
    InvalidBindAddress,
    InvalidNetwork,
    NetworkDown,
    UnreachableHost,
    MessageSerialization,
    Timeout,
    Other,
    SessionNotFound,
    Serialization,
    Encryption,
    InvalidSession,
    Receiving,
    ZenohError,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionMessage {
    pub message: MessageData,
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message: String,
}

pub trait MessageListener {
    fn listen(&self) -> Result<SessionMessage, MessagingError>;
}

pub trait Messageble {
    fn read_message(&self) -> Result<SessionMessage, MessagingError>;
    fn send_message(&self, message: SessionMessage) -> Result<(), MessagingError>;
}

pub trait MessagebleTopicAsync {
    fn read_message(
        &self,
        topic: &str,
    ) -> impl std::future::Future<Output = Result<SessionMessage, MessagingError>> + Send;
    fn send_message(
        &self,
        topic: &str,
        message: SessionMessage,
    ) -> impl std::future::Future<Output = Result<(), MessagingError>> + Send;
}

pub trait MessagebleTopicAsyncReadTimeout {
    fn read_message_timeout(
        &self,
        topic: &str,
        timeout: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<SessionMessage, MessagingError>> + Send;
    fn read_messages_timeout(
        &self,
        topic: &str,
        timeout: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<Vec<SessionMessage>, MessagingError>> + Send;
}

pub trait MessagebleTopicAsyncPublishReads {
    fn read_messages(
        &self,
        topic: &str,
        channel: &mpsc::Sender<(String, String)>,
    ) -> impl std::future::Future<Output = Result<(), MessagingError>> + Send;
}

impl SessionMessage {
    pub fn new_init(pub_key: String, signature: String, challenge: &mut String) -> Self {
        *challenge = generate_random_string(challenge_len());
        SessionMessage {
            message: MessageData::Init(InitMsg {
                pub_key,
                signature,
                challenge: challenge.clone(),
            }),
            session_id: "".to_string(),
        }
    }

    pub fn new_init_ok(
        sym_key_encrypted: String,
        pub_key: String,
        orig_pub_key: String,
        challenge_sig: String,
    ) -> Self {
        SessionMessage {
            message: MessageData::InitOk(InitOkMsg {
                sym_key_encrypted,
                pub_key,
                orig_pub_key,
                challenge_sig,
            }),
            session_id: "".to_string(),
        }
    }
    pub fn new_init_await(orig_pub_key: String, pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::InitAwait(InitAwaitMsg {
                orig_pub_key,
                pub_key,
            }),
            session_id: "".to_string(),
        }
    }
    pub fn new_init_decline(pub_key: String, message: String) -> Self {
        SessionMessage {
            message: MessageData::InitDecline(InitDeclineMsg { pub_key, message }),
            session_id: "".to_string(),
        }
    }
    pub fn new_chat(message: String, sender_userid: String, sender_fingerprint: String) -> Self {
        SessionMessage {
            message: MessageData::Chat(ChatMsg {
                message: message,
                sender_userid,
                sender_fingerprint,
                date_time: get_current_datetime(),
            }),
            session_id: "".to_string(),
        }
    }

    pub fn new_discovery(pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::Discovery(DiscoveryMsg { pub_key }),
            session_id: "".to_string(),
        }
    }

    pub fn new_discovery_reply(pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::DiscoveryReply(DiscoveryReplyMsg { pub_key }),
            session_id: "".to_string(),
        }
    }

    pub fn new_internal(session_id: String, message: String, topic: String) -> Self {
        SessionMessage {
            message: MessageData::Internal(InternalMsg { message, topic }),
            session_id,
        }
    }

    pub fn new_close(session_id: String, pub_key: String, signature: String) -> Self {
        SessionMessage {
            message: MessageData::Close(CloseMsg {
                session_id: session_id.clone(),
                pub_key,
                signature,
            }),
            session_id: session_id.clone(),
        }
    }

    pub fn new_heartbeat(session_id: String) -> Self {
        SessionMessage {
            message: MessageData::Heartbeat(HeartbeatMsg {}),
            session_id: session_id.clone(),
        }
    }

    pub fn new_replay(key_id: String) -> Self {
        SessionMessage {
            message: MessageData::Replay(ReplayMsg {
                key_id: key_id.clone(),
            }),
            session_id: "".to_string(),
        }
    }

    pub fn new_email(session_id: String, encrypted_msg: EncryptedMsg) -> Self {
        SessionMessage {
            message: MessageData::Email(EmailMsg {
                message: encrypted_msg,
                session_id,
            }),
            session_id: "".into(),
        }
    }

    pub fn new_replay_response(session_id: String, messages: Vec<SessionMessage>) -> Self {
        SessionMessage {
            message: MessageData::ReplayResponse(ReplayResponseMsg {
                session_id: session_id.clone(),
                messages,
            }),
            session_id: session_id.clone(),
        }
    }

    pub fn new_from_data(id: String, data: MessageData) -> Self {
        SessionMessage {
            message: data.clone(),
            session_id: id,
        }
    }

    pub fn serialize(&self) -> Result<String, serde_cbor::Error> {
        // Convert the message to a JSON string
        let serialized = serde_cbor::to_vec(self)?;

        // Encode the JSON string as base64
        let encoded = base64::encode(serialized);

        Ok(encoded)
    }

    pub fn deserialize(encoded_message: &str) -> Result<Self, ()> {
        // Decode the base64 string into bytes
        let bytes = base64::decode(encoded_message).map_err(|_| ())?;

        // Deserialize the CBOR bytes into the struct
        let message = serde_cbor::from_slice(&bytes).map_err(|_| ())?;

        Ok(message)
    }

    pub fn to_string(&self) -> String {
        match &self.message {
            MessageData::Init(msg) => msg.pub_key.clone(),
            MessageData::InitOk(msg) => msg.sym_key_encrypted.clone(),
            MessageData::Close(msg) => msg.session_id.clone(),
            MessageData::Chat(msg) => msg.message.clone(),
            MessageData::Encrypted(msg) => msg.data.clone(),
            _ => return "TODO".to_string(),
        }
    }
}
