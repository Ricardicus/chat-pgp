//! Hello World server in Rust
//! Binds REP socket to tcp://*:5555
//! Expects "Hello" from client, replies with "World"
#![allow(dead_code)]

use std::env;

mod session;
use session::Session;

use session::crypto::{ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt};
use session::middleware::ZMQHandler;

use clap::Parser;

use ncurses::*;

mod util;

mod pgp;
use pgp::pgp::read_from_gpg;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[clap(short, long)]
    #[arg(default_value = "")]
    gpgkey: String,

    #[clap(short, long)]
    #[arg(default_value = "unset")]
    tty: String,
}

fn main() {
    let cli = Cli::parse();
    let context = zmq::Context::new();
    let _responder = context.socket(zmq::REP).unwrap();
    let _sessions = Vec::<Session<ChaCha20Poly1305EnDeCrypt, PGPEnDeCrypt>>::new();

    let gpgkey = cli.gpgkey;
    let tty = cli.tty;

    if tty != "unset" {
        println!("setting gpg tty");
        env::set_var("GPG_TTY", tty);
    }

    if gpgkey.len() > 0 {
        // Starct curses mode
        initscr();
        noecho();

        addstr(format!("Passphrase for gpgkey {}: ", gpgkey).as_str());
        refresh();

        let mut passphrase = String::new();
        getstr(&mut passphrase);

        echo();
        endwin();

        let cert =
            read_from_gpg(&gpgkey, Some(passphrase.as_str())).expect("Failed to read gpg key");
        let _pub_key = cert.primary_key().to_string();

        let pgp_handler = PGPEnDeCrypt::new(&cert, &passphrase);
        let mut session = Session::new(pgp_handler);
        let address = "tcp://*:5555";
        let handler = ZMQHandler::new_responder(address);

        //session.serve(&handler);
    } else {
        println!("Set gpg key.. this does not work otherwise..");
        return;
    }
}
