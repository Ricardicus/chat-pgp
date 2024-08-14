// Define an enum with your topics
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Topic {
    Initialize,
    Discover,
    Message,
}

impl Topic {
    // Method to convert enum to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Topic::Initialize => "session/initialize",
            Topic::Discover => "session/discover",
            Topic::Message => "session/message",
        }
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
}
