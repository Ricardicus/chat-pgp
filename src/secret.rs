use sodiumoxide::crypto::secretbox;
use message::CryptedMessage;
use serde::{Serialize, Deserialize};
use serde_json::{to_string, from_str};

#[derive(Debug)]
