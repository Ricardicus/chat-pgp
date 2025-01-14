use crate::session::messages::SessionMessage;
use crate::util::get_current_datetime;
use serde::{Deserialize, Serialize};
use serde_cbor;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionLogMessage {
    pub message: SessionMessage,
    pub read: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SessionLog {
    pub session_id: String,
    pub encrypted_session_key: String,
    pub last_active: String,
    pub others: Vec<String>,
    pub messages: Vec<SessionLogMessage>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Memory {
    session_log: HashMap<String, SessionLog>,
    file: String,
}

impl Memory {
    /// Creates a new empty Memory instance.
    pub fn new(file: &str) -> Self {
        Self {
            session_log: HashMap::new(),
            file: file.to_string(),
        }
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
        let memory: Memory = serde_cbor::from_slice(&buffer).expect("Failed to deserialize Memory");
        Ok(memory)
    }

    /// Creates a new SessionLog with empty messages and stores it in the session_log.
    pub fn new_entry(
        &mut self,
        session_id: String,
        encrypted_session_key: String,
        others: Vec<String>,
    ) {
        let session_log = SessionLog {
            session_id: session_id.clone(),
            encrypted_session_key,
            messages: Vec::new(),
            others,
            last_active: get_current_datetime(),
        };
        self.session_log.insert(session_id, session_log);
    }

    /// Adds a SessionMessage to the messages vector of the given session_id.
    /// Returns Result<(), ()> where Err(()) is returned if the session_id does not exist.
    pub fn add_entry_message(
        &mut self,
        session_id: &str,
        message: SessionMessage,
    ) -> Result<(), ()> {
        if let Some(session_log) = self.session_log.get_mut(session_id) {
            let session_log_message = SessionLogMessage {
                read: true,
                message,
            };
            session_log.messages.push(session_log_message);
            session_log.last_active = get_current_datetime();
            Ok(())
        } else {
            Err(())
        }
    }

    /// Returns a Vec of Strings containing the session_ids in the session_log.
    pub fn get_session_ids(&self) -> Vec<String> {
        let mut session_logs: Vec<&SessionLog> = self.session_log.values().collect();
        session_logs.sort_by(|a, b| b.last_active.cmp(&a.last_active));
        session_logs
            .iter()
            .map(|log| log.session_id.clone())
            .collect()
    }

    pub fn in_memory(&self, session_id: &str) -> bool {
        match self.session_log.get(session_id) {
            Some(_) => true,
            None => false,
        }
    }

    pub fn get_encrypted_sym_key(&self, session_id: &str) -> Result<String, ()> {
        match self.session_log.get(session_id) {
            Some(entry) => Ok(entry.encrypted_session_key.clone()),
            None => Err(()),
        }
    }

    pub fn get_others(&self, session_id: &str) -> Result<Vec<String>, ()> {
        match self.session_log.get(session_id) {
            Some(entry) => Ok(entry.others.clone()),
            None => Err(()),
        }
    }
    pub fn get_length(&self, session_id: &str) -> Result<usize, ()> {
        match self.session_log.get(session_id) {
            Some(entry) => Ok(entry.messages.len()),
            None => Err(()),
        }
    }
    pub fn get_last_active(&self, session_id: &str) -> Result<String, ()> {
        match self.session_log.get(session_id) {
            Some(entry) => Ok(entry.last_active.clone()),
            None => Err(()),
        }
    }
    pub fn delete_session(&mut self, session_id: &str) -> Result<usize, ()> {
        match self.session_log.remove(session_id) {
            Some(entry) => Ok(entry.messages.len()),
            None => Err(()),
        }
    }
    /// Returns a tuple with the encrypted session key and a vector of session messages
    /// for the given session_id. Returns Err(()) if the session_id does not exist.
    pub fn get_session_log(
        &self,
        session_id: &str,
    ) -> Result<(String, Vec<SessionLogMessage>), ()> {
        if let Some(session_log) = self.session_log.get(session_id) {
            Ok((
                session_log.encrypted_session_key.clone(),
                session_log.messages.clone(),
            ))
        } else {
            Err(())
        }
    }
}
