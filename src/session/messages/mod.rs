use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Clone)]
pub enum EncryptionType {
    Assymetric,
    Symmetric,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct InitMsg {
    pub pub_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InitOkMsg {
    pub sym_key: String,
    pub orig_pub_key: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct InitAwaitMsg {
    pub sym_key: String,
    pub orig_pub_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPassMsg {
    pub sym_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CloseMsg {
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMsg {
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CloseOkMsg {
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PingMsg {}

#[derive(Serialize, Deserialize, Clone)]
pub struct PongMsg {}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedMsg {
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DiscoveryMsg {
    pub pub_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InternalMsg {
    pub message: String,
    pub topic: String,
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone)]
pub enum SessionErrorCodes {
    Serialization = 1,
    InvalidMessage = 2,
    InvalidPublicKey = 3,
    Encryption = 4,
    Timeout = 5,
    Protocol = 6,
    NotAccepted = 7,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionErrorMsg {
    pub code: u32,
    pub message: String,
}

// Define an enum to encapsulate different message data types
#[derive(Serialize, Deserialize, Clone)]
pub enum MessageData {
    Init(InitMsg),
    InitOk(InitOkMsg),
    InitAwait(InitAwaitMsg),
    Close(CloseMsg),
    CloseOk(CloseOkMsg),
    Chat(ChatMsg),
    Ping(PingMsg),
    Pong(PongMsg),
    Encrypted(EncryptedMsg),
    SessionError(SessionErrorMsg),
    KeyPass(KeyPassMsg),
    Discovery(DiscoveryMsg),
    Internal(InternalMsg),
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
}

#[derive(Serialize, Deserialize, Clone)]
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
    pub fn new_init(pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::Init(InitMsg { pub_key }),
            session_id: "".to_string(),
        }
    }

    pub fn new_init_ok(sym_key: String, orig_pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::InitOk(InitOkMsg {
                sym_key,
                orig_pub_key,
            }),
            session_id: "".to_string(),
        }
    }
    pub fn new_init_await(sym_key: String, orig_pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::InitAwait(InitAwaitMsg {
                sym_key,
                orig_pub_key,
            }),
            session_id: "".to_string(),
        }
    }

    pub fn new_chat(message: String) -> Self {
        SessionMessage {
            message: MessageData::Chat(ChatMsg { message: message }),
            session_id: "".to_string(),
        }
    }

    pub fn new_discovery(pub_key: String) -> Self {
        SessionMessage {
            message: MessageData::Discovery(DiscoveryMsg { pub_key }),
            session_id: "".to_string(),
        }
    }

    pub fn new_internal(session_id: String, message: String, topic: String) -> Self {
        SessionMessage {
            message: MessageData::Internal(InternalMsg { message, topic }),
            session_id,
        }
    }

    pub fn new_close(data: String) -> Self {
        SessionMessage {
            message: MessageData::Close(CloseMsg { data: data }),
            session_id: "".to_string(),
        }
    }

    pub fn serialize(&self) -> Result<String, serde_json::Error> {
        // Convert the message to a JSON string
        let json = serde_json::to_string(self)?;

        // Encode the JSON string as base64
        let encoded = base64::encode(json);

        Ok(encoded)
    }

    pub fn deserialize(encoded_message: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = base64::decode(encoded_message)?;
        let message = serde_json::from_slice(&bytes)?;
        Ok(message)
    }

    pub fn to_string(&self) -> String {
        match &self.message {
            MessageData::Init(msg) => msg.pub_key.clone(),
            MessageData::InitOk(msg) => msg.sym_key.clone(),
            MessageData::Close(msg) => msg.data.clone(),
            MessageData::Chat(msg) => msg.message.clone(),
            MessageData::Encrypted(msg) => msg.data.clone(),
            _ => return "TODO".to_string(),
        }
    }
}
