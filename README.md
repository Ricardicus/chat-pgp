# PGP Chat

Welcome to PGP chat. This in a encrypted chat platform based on [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy).
The idea is to create a simple chat platform that is based on strong encryption. 

## Encryption

Each chat session is encrypted using a symmectrical ChaCha20Poly1305 algorithm
with a shared secret that is protected with PGP assymetrical
encryption. If you are unfamiliar with OpenPGP and using GnuPG then see this [GnuPG guide](https://www.gnupg.org/gph/en/manual/c14.html). 

## Communication

The communication protocol is built on [Zenoh](https://github.com/eclipse-zenoh/zenoh).

## Work in progress

This is a work in progress. So far I have this:

- PGP assymetrical encryption using pre-existing pgp-keys (you can create them with gpg)
- Topic based middleware using Zenoh

Will work on this:

- Web front end + API:ification of the Rust backend.
- Better terminal interface

Please feel free to test and come with feedback. This project is in its early stage
and I would appreciate contributions if you agree with this vision.

