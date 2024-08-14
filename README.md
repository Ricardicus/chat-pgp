# PGP Chat

Welcome to PGP chat. This in a encrypted chat platform based on [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy).

## Encryption

You session is encrypted using ChaCha20Poly1305 with a 
session key that is protected with PGP key assymetrical
encryption.

## Communication

The communication protocol is built on [Zenoh](https://github.com/eclipse-zenoh/zenoh).

## Work in progress

This is a work in progress. So far I have this:

- PGP assymetrical encryption using pre-existing pgp-keys (you can create them with gpg)
- Topic based middleware using Zenoh

Will work on this:

- Web front end
- Hosting middleware peers that enable communications behind routers


