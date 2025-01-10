use crate::session::messages::EmailMsg;
use serde::{Deserialize, Serialize};
use serde_cbor;
use std::fs::File;
use std::io::{self, Read, Write};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InboxEntry {
    pub message: EmailMsg,
    pub id: String,
    pub read: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Inbox {
    entries: Vec<InboxEntry>,
    file: String,
}

impl Inbox {
    /// Creates a new empty Memory instance.
    pub fn new(file: &str) -> Self {
        Self {
            entries: Vec::new(),
            file: file.to_string(),
        }
    }

    pub fn get_entries(&self) -> Vec<InboxEntry> {
        self.entries.clone()
    }

    /// Serializes the Memory struct to an array of bytes using CBOR.
    fn serialize(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("Failed to serialize Memory")
    }

    /// Writes the serialized content of Memory to a file at the given path.
    pub fn to_file(&self) -> io::Result<()> {
        let serialized = self.serialize();
        let mut file = File::create(&self.file)?;
        file.write_all(&serialized)?;
        Ok(())
    }

    /// Reads the serialized content from a file at the given path and deserializes it into a Memory struct.
    pub fn from_file(path: &str) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let inbox: Inbox = serde_cbor::from_slice(&buffer).expect("Failed to deserialize Memory");
        Ok(inbox)
    }

    pub fn add_entry(&mut self, message: EmailMsg) -> bool {
        // Check if the email ID already exists in the inbox entries
        let id = message.get_id();
        if self.entries.iter().any(|entry| entry.id == id) {
            // If the ID exists, do not add the entry
            return false;
        }

        // Create a new InboxEntry with the provided message
        let new_entry = InboxEntry {
            message: message.clone(),
            id,
            read: false, // New messages are marked as unread by default
        };

        // Add the new entry to the entries vector
        self.entries.push(new_entry);

        // Return true indicating the entry was successfully added
        true
    }
}
