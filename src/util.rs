use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::process::Command;

extern crate base64;
extern crate chrono;
use chrono::{DateTime, Utc};

pub fn execute_command(command: &str) -> Result<String, String> {
    // Split the command string into words
    let mut parts = command.split_whitespace();

    // The first word is the executable
    let executable = parts
        .next()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "No executable provided")
        })
        .expect("Failed to parse command");

    // Execute the command and collect its output
    let result = Command::new(executable)
        .args(parts.clone())
        .output()
        .expect(&format!(
            "Failed to execute command: {} {:?}",
            &executable, parts
        ));

    // Extracting the stdout, stderr, and status from the result
    let stdout = String::from_utf8(result.stdout).expect("Output was not valid UTF-8");
    let stderr = String::from_utf8(result.stderr).expect("Error output was not valid UTF-8");
    let status = result.status;

    if status.success() {
        Ok(stdout)
    } else {
        if stderr.len() == 0 {
            return Err(stdout);
        }
        Err(stderr)
    }
}

pub fn short_fingerprint(fingerprint: &str) -> String {
    if fingerprint.len() > 8 {
        let first_four = &fingerprint[0..4];
        let last_four = &fingerprint[fingerprint.len() - 4..];
        format!("{}...{}", first_four, last_four)
    } else {
        fingerprint.to_string()
    }
}

pub fn get_current_datetime() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn generate_random_string(length: usize) -> String {
    let mut rng = thread_rng();
    let random_string: String = (0..length)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    random_string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingBuffer<T> {
    buffer: Vec<T>,
    capacity: usize,
    start: usize,
    end: usize,
    is_full: bool,
}

impl<T> RingBuffer<T> {
    /// Creates a new `RingBuffer` with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Capacity must be greater than 0");
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
            start: 0,
            end: 0,
            is_full: false,
        }
    }

    /// Retrieves the element at the logical index `index` in the ring buffer.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len() {
            None
        } else {
            let physical_index = (self.start + index) % self.capacity;
            self.buffer.get(physical_index)
        }
    }

    /// Pushes an item into the ring buffer. Overwrites the oldest item if the buffer is full.
    pub fn push(&mut self, item: T) {
        if self.buffer.len() < self.capacity {
            self.buffer.push(item);
        } else {
            self.buffer[self.end] = item;
        }

        self.end = (self.end + 1) % self.capacity;
        if self.is_full {
            self.start = (self.start + 1) % self.capacity; // Overwrite oldest element
        } else if self.end == self.start {
            self.is_full = true;
        }
    }

    /// Returns the number of elements in the ring buffer.
    pub fn len(&self) -> usize {
        if self.is_full {
            self.capacity
        } else if self.end >= self.start {
            self.end - self.start
        } else {
            self.capacity - (self.start - self.end)
        }
    }
}
