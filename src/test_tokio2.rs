use std::sync::Arc;
use std::io::{self, Write};

use tokio::sync::{mpsc, Mutex, Notify, OnceCell, Semaphore};
use tokio::time::{timeout, Duration};

pub struct WindowPipe<T> {
    pub tx: mpsc::Sender<T>,
    pub rx: Mutex<mpsc::Receiver<T>>,
}

impl<T> WindowPipe<T> {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::channel(50);
        Self {
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn read(&self) -> Result<T, ()> {
        match self.rx.lock().await.recv().await {
            Some(msg) => Ok(msg),
            None => Err(()),
        }
    }

    pub async fn send(&self, cmd: T) {
        let _ = self.tx.send(cmd).await;
    }
}

static PIPE: OnceCell<WindowPipe<String>> = OnceCell::const_new();

async fn initialize_global_values() {
    // Directly initialize the GLOBAL_VALUE using `init`
    let _ = PIPE.set(WindowPipe::<String>::new());
}

pub async fn read_terminal_input() -> Result<String, ()> {
    match PIPE.get().unwrap().read().await {
        Ok(cmd) => Ok(cmd),
        Err(_) => Err(()),
    }
}

async fn send_terminal_input(message: String) {
    let _ = PIPE.get().unwrap().send(message).await;
}

#[tokio::main]
async fn main() {
    // First task to initialize the global value
    let initializer = tokio::spawn(async {
        initialize_global_values().await;
    });

    // Wait for the initializer to complete
    initializer.await.unwrap();

    tokio::spawn(async move {
        loop {
            let mut input = String::new();

            print!("Please enter something: ");
            io::stdout().flush().unwrap(); // Make sure the prompt is printed before waiting for input

            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");
            send_terminal_input(input).await;
        }
    });
    let l = tokio::spawn(async move {
        loop {
            println!("reading..");
            let r = read_terminal_input().await;
            if r.is_ok() {
                println!("you entered: {}", r.unwrap());
            }
        }
    });

    l.await;
}
