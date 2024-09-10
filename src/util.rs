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

pub fn get_current_datetime() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}
