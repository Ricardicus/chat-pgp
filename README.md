# Chat-PGP

Welcome to chat PGP. This is an encrypted chat platform based on [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy).

The idea is to create a simple chat platform that is based on strong encryption. 

## Encryption

Each chat session is encrypted using a symmectrical ChaCha20Poly1305 algorithm
with a shared secret that is protected with PGP assymetrical
encryption. If you are unfamiliar with OpenPGP and using GnuPG then see this [GnuPG guide](https://www.gnupg.org/gph/en/manual/c14.html). 

## Communication

The communication protocol is built on [Zenoh](https://github.com/eclipse-zenoh/zenoh).

Zenoh is an extremely flexible middleware that does not force a network topology onto
the project. By providing a configuration file to zenoh, one can configure the entire network oneself; 
so that one does not have to rely on routers and peers someone else setup for
this project. There is support for TLS (one- and two-way) authentication in zenoh.

By default, I have set up a router running on a Digital Ocean Droplet, in a server they claim to be running in Amsterdam.
Starting a zenoh router is very simple. I just launch the zenoh daemon, zenohd.
You can provide your own router configuration by passing the "-z" flag to the program.
By default, however, the client program will connect with other peers via this aforementioned router as specified in [zenoh/config.json5](https://github.com/Ricardicus/chat-pgp/blob/master/zenoh/config.json5): 
```bash
{
  "mode": "client",
  "connect": {
    "endpoints": ["tcp/174.138.5.172:443"]
  }
}
```

What I am writing is that you can launch your own network by installing zenohd and changing the "endpoints" in the configuration file above.
You can also configure the base TCP/IP connection to be secured with TLS with your own certificates if you want, however, the application level traffic is already encrypted.

## Work in progress

This is a work in progress. So far I have this:

- PGP assymetrical encryption using pre-existing pgp-keys (you can create them with gpg)
- Communcations based on Zenoh
- Encrypted one-to-one online chat in terminal (ncurses) interface.

Will work on this:

- Better terminal interface (ncurses) in the near term
- Web front end (on localhost) in the long term
- Apply local gpg keychain as policy for session key verification
- PGP session key signed by main key instead of using the main key for each session establishment

Please feel free to test and come with feedback. This project is in its early stage
and I would appreciate contributions if you agree with this vision.

