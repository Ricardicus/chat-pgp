use serde::{Serialize, Deserialize};
use serde_json::{to_string, from_str};
use util::get_current_datetime;

#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    sender: String,
    session: String,
    content: String,
    timestamp: String,
}

fn chat_msg_create(sender: &str, session: &str, content: &str) -> ChatMessage {
    ChatMessage {
        sender: sender.to_string(),
        session: session.to_string(),
        content: content.to_string(),
        timestamp: get_current_datetime(),
    }
}

fn chat_msg_serialize(msg: &ChatMessage) -> Result<String, serde_json::Error> {
    to_string(msg)
}

fn chat_msg_deserialize(msg: &str) -> Result<ChatMessage, serde_json::Error> {
    from_str(msg)
} 

struct CryptedMessage {
    session: String,
    content: String,
    timestamp: String,
}

fn crypted_msg_create(session: &str, content: &str) -> CryptedMessage {
    CryptedMessage {
        session: session.to_string(),
        content: content.to_string(),
        timestamp: get_current_datetime(),
    }
}

fn crypted_msg_serialize(msg: &CryptedMessage) -> Result<String, serde_json::Error> {
    to_string(msg)
}

fn crypted_msg_deserialize(msg: &str) -> Result<CryptedMessage, serde_json::Error> {
    from_str(msg)
}
