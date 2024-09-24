// Define an enum with your topics
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Topic {
    Initialize,
    Discover,
    Message,
    Errors,
    Internal,
    Close,
    Heartbeat,
}

impl Topic {
    // Method to convert enum to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Topic::Initialize => "v1/session/initialize",
            Topic::Discover => "v1/session/discover",
            Topic::Message => "v1/session/message",
            Topic::Errors => "v1/errors",
            Topic::Internal => "v1/internal",
            Topic::Close => "v1/session/close",
            Topic::Heartbeat => "v1/session/heartbeat",
        }
    }

    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
    pub fn as_reply(&self) -> String {
        let mut s = self.as_str().to_string();
        s.push_str(Topic::reply_suffix());
        s
    }
    pub fn reply_suffix() -> &'static str {
        "/reply"
    }
    pub fn messaging_topic_in(fingerprint: &str) -> String {
        let mut t = Topic::Message.as_str().to_string();
        t.push_str("/");
        t.push_str(fingerprint);
        t.push_str("/in");
        t
    }
    pub fn messaging_topic_out(fingerprint: &str) -> String {
        let mut t = Topic::Message.as_str().to_string();
        t.push_str("/");
        t.push_str(fingerprint);
        t.push_str("/out");
        t
    }
    pub fn close_topic(fingerprint: &str) -> String {
        let mut t = Topic::Close.as_str().to_string();
        t.push_str("/");
        t.push_str(fingerprint);
        t
    }
    pub fn init_topic(fingerprint: &str) -> String {
        let mut t = Topic::Initialize.as_str().to_string();
        t.push_str("/");
        t.push_str(fingerprint);
        t
    }
    pub fn heartbeat_topic(fingerprint: &str) -> String {
        let mut t = Topic::Heartbeat.as_str().to_string();
        t.push_str("/");
        t.push_str(fingerprint);
        t
    }
}

pub fn challenge_len() -> usize {
    30
}
