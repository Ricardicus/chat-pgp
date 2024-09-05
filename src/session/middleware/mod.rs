use crate::session::messages::{
    MessageListener, Messageble, MessagebleTopicAsync, MessagebleTopicAsyncPublishReads,
    MessagebleTopicAsyncReadTimeout, MessagingError, SessionErrorCodes, SessionErrorMsg,
    SessionMessage,
};
use crate::session::Session;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use zenoh::prelude::*;

use tokio::time::timeout;

pub struct ZMQHandler {
    context: zmq::Context,
    socket: zmq::Socket,
}

impl ZMQHandler {
    pub fn new_responder(address: &str) -> Self {
        let context = zmq::Context::new();
        let responder = context.socket(zmq::REP).unwrap();
        responder.bind(address).unwrap();
        ZMQHandler {
            context,
            socket: responder,
        }
    }
    pub fn new_requester(address: &str) -> Self {
        let context = zmq::Context::new();
        let requester = context.socket(zmq::REQ).unwrap();
        requester.connect(address).unwrap();
        ZMQHandler {
            context,
            socket: requester,
        }
    }
}

impl MessageListener for ZMQHandler {
    fn listen(&self) -> Result<SessionMessage, MessagingError> {
        let mut msg = zmq::Message::new();
        match self.socket.recv(&mut msg, 0) {
            Ok(_) => match Session::parse_message(&msg.as_str().unwrap()) {
                Ok(message) => Ok(message),
                Err(_) => Err(MessagingError::MessageSerialization),
            },
            Err(zmq::Error::EADDRINUSE) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EADDRNOTAVAIL) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EHOSTUNREACH) => return Err(MessagingError::UnreachableHost),
            Err(zmq::Error::ENETDOWN) => return Err(MessagingError::NetworkDown),
            Err(_e) => return Err(MessagingError::Other),
        }
    }
}

impl Messageble for ZMQHandler {
    fn send_message(&self, message: SessionMessage) -> Result<(), MessagingError> {
        let message = message.serialize().unwrap();
        match self.socket.send(&message, 0) {
            Ok(_) => Ok(()),
            Err(zmq::Error::EADDRINUSE) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EADDRNOTAVAIL) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EHOSTUNREACH) => return Err(MessagingError::UnreachableHost),
            Err(zmq::Error::ENETDOWN) => return Err(MessagingError::NetworkDown),
            Err(_e) => return Err(MessagingError::Other),
        }
    }
    fn read_message(&self) -> Result<SessionMessage, MessagingError> {
        let mut msg = zmq::Message::new();
        match self.socket.recv(&mut msg, 0) {
            Ok(_) => match Session::parse_message(&msg.as_str().unwrap()) {
                Ok(message) => Ok(message),
                Err(_) => Err(MessagingError::MessageSerialization),
            },
            Err(zmq::Error::EADDRINUSE) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EADDRNOTAVAIL) => return Err(MessagingError::InvalidBindAddress),
            Err(zmq::Error::EHOSTUNREACH) => return Err(MessagingError::UnreachableHost),
            Err(zmq::Error::ENETDOWN) => return Err(MessagingError::NetworkDown),
            Err(_) => return Err(MessagingError::Other),
        }
    }
}

pub struct ZenohHandler {
    session: Arc<Mutex<zenoh::Session>>,
}

impl ZenohHandler {
    pub fn new(session: Arc<Mutex<zenoh::Session>>) -> Self {
        ZenohHandler { session }
    }
}

impl MessagebleTopicAsync for ZenohHandler {
    async fn read_message(&self, topic: &str) -> Result<SessionMessage, MessagingError> {
        let s = self.session.lock().await;
        let subscriber = zenoh::AsyncResolve::res(s.declare_subscriber(topic))
            .await
            .unwrap();
        match subscriber.recv_async().await {
            Ok(incoming) => {
                let incoming = incoming
                    .payload()
                    .deserialize::<String>()
                    .unwrap_or_else(|e| format!("{}", e));
                return match SessionMessage::deserialize(&incoming) {
                    Ok(message) => Ok(message),
                    Err(_) => {
                        return Err(MessagingError::Serialization);
                    }
                };
            }
            Err(_) => Err(MessagingError::InvalidSession),
        }
    }

    async fn send_message(
        &self,
        topic: &str,
        message: SessionMessage,
    ) -> Result<(), MessagingError> {
        let message = message.serialize().unwrap();
        let s = self.session.lock().await;

        zenoh::AsyncResolve::res(s.put(topic, message))
            .await
            .unwrap();
        Ok(())
    }
}

impl MessagebleTopicAsyncPublishReads for ZenohHandler {
    async fn read_messages(
        &self,
        topic: &str,
        channel: &mpsc::Sender<(String, String)>,
    ) -> Result<(), MessagingError> {
        let mut topic_in = topic.to_string();
        let s = self.session.lock().await;
        let subscriber = zenoh::AsyncResolve::res(s.declare_subscriber(topic))
            .await
            .unwrap();
        loop {
            let msg = match subscriber.recv_async().await {
                Ok(incoming) => {
                    topic_in = incoming.key_expr().to_string();
                    let incoming = incoming
                        .payload()
                        .deserialize::<String>()
                        .unwrap_or_else(|e| format!("{}", e));
                    match SessionMessage::deserialize(&incoming) {
                        Ok(message) => Ok(message),
                        Err(_) => {
                            return Err(MessagingError::Serialization);
                        }
                    }
                }
                Err(_) => Err(MessagingError::InvalidSession),
            };
            match msg {
                Ok(m) => {
                    let val = match m.serialize() {
                        Ok(v) => v,
                        Err(_) => return Err(MessagingError::InvalidSession),
                    };
                    match channel.send((topic_in.to_string(), val)).await {
                        Ok(_) => {}
                        Err(_) => return Err(MessagingError::InvalidSession),
                    }
                }
                Err(_) => return Err(MessagingError::InvalidSession),
            };
        }
    }
}

impl MessagebleTopicAsyncReadTimeout for ZenohHandler {
    async fn read_message_timeout(
        &self,
        topic: &str,
        timeout_duration: std::time::Duration,
    ) -> Result<SessionMessage, MessagingError> {
        let s = self.session.lock().await;
        let subscriber = zenoh::AsyncResolve::res(s.declare_subscriber(topic))
            .await
            .unwrap();
        match timeout(timeout_duration, subscriber.recv_async()).await {
            Ok(incoming) => {
                let incoming = incoming
                    .unwrap()
                    .payload()
                    .deserialize::<String>()
                    .unwrap_or_else(|e| format!("{}", e));
                let incoming_str = incoming.to_string();
                match SessionMessage::deserialize(&incoming_str) {
                    Ok(msg) => Ok(msg),
                    Err(_) => Err(MessagingError::Serialization),
                }
            }
            Err(_) => Err(MessagingError::Timeout),
        }
    }
    async fn read_messages_timeout(
        &self,
        topic: &str,
        timeout_duration: Duration,
    ) -> Result<Vec<SessionMessage>, MessagingError> {
        let mut messages = Vec::new();
        let s = self.session.lock().await;
        let subscriber = zenoh::AsyncResolve::res(s.declare_subscriber(topic))
            .await
            .unwrap();

        let end_time = Instant::now() + timeout_duration;

        loop {
            let remaining_time = end_time.saturating_duration_since(Instant::now());
            if remaining_time.is_zero() {
                break;
            }

            match timeout(remaining_time, subscriber.recv_async()).await {
                Ok(Ok(incoming)) => {
                    let incoming = incoming
                        .payload()
                        .deserialize::<String>()
                        .unwrap_or_else(|e| format!("{}", e));
                    let incoming_str = incoming.to_string();
                    match SessionMessage::deserialize(&incoming_str) {
                        Ok(msg) => messages.push(msg),
                        Err(_) => return Err(MessagingError::Serialization),
                    }
                }
                Ok(Err(_)) => return Err(MessagingError::Receiving),
                Err(_) => break, // Timeout occurred
            }
        }

        if messages.is_empty() {
            Err(MessagingError::Timeout)
        } else {
            Ok(messages)
        }
    }
}
