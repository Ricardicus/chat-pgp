# PGP Chat

Chat encrypted with PGP with anyone else.

## Encryption

You session is encrypted using ChaCha20Poly1305 with a 
session key that is protected with PGP key assymetrical
encryption.

## Work in progress

This is a work in progress. So far I have this:

- PGP assymetrical encryption using pre-existing pgp-keys (you can create them with gpg)
- Topic based middleware using Zenoh

Will work on this:

- Web front end
- Hosting middleware peers that enable communications behind routers


