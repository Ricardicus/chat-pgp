extern crate sequoia_openpgp as openpgp;
use aead::generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use openpgp::policy::StandardPolicy as P;
use openpgp::Cert;

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::pgp::*;

// Define the trait Cryptical
pub trait Cryptical {
    fn get_public_key_as_base64(&self) -> String;
    fn get_public_key_fingerprint(&self) -> String;
}
pub trait CrypticalEncrypt {
    fn encrypt(&self, input: &str) -> Result<String, String>;
}
pub trait CrypticalDecrypt {
    fn decrypt(&self, input: &str) -> Result<String, String>;
}
pub trait CrypticalID {
    fn get_userid(&self) -> String;
}

#[derive(Clone)]
pub struct ChaCha20Poly1305EnDeCrypt {
    pub key: String,
}

impl ChaCha20Poly1305EnDeCrypt {
    pub fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        ChaCha20Poly1305EnDeCrypt {
            key: base64::encode(key.as_slice()),
        }
    }
    pub fn new_from_str(key: &str) -> Self {
        ChaCha20Poly1305EnDeCrypt {
            key: key.to_owned(),
        }
    }
}

impl Cryptical for ChaCha20Poly1305EnDeCrypt {
    fn get_public_key_as_base64(&self) -> String {
        self.key.clone()
    }
    fn get_public_key_fingerprint(&self) -> String {
        self.get_public_key_as_base64()
    }
}

impl CrypticalEncrypt for ChaCha20Poly1305EnDeCrypt {
    fn encrypt(&self, input: &str) -> Result<String, String> {
        let key = match base64::decode(&self.key) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid base64 key")),
        };
        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid ChaCha20Poly1305 key")),
        };
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = match cipher.encrypt(&nonce, input.as_bytes()) {
            Ok(res) => res,
            Err(_) => return Err(String::from("ChaCha20Poly1305 failure to encrypt")),
        };

        let mut result = Vec::<u8>::new();
        for &i in nonce.iter() {
            result.push(i);
        }
        for &i in ciphertext.iter() {
            result.push(i);
        }
        Ok(base64::encode(result))
    }
}

impl CrypticalDecrypt for ChaCha20Poly1305EnDeCrypt {
    fn decrypt(&self, input: &str) -> Result<String, String> {
        let key = match base64::decode(&self.key) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid base64 key")),
        };

        let input_base64decoded = match base64::decode(input) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid base64 input")),
        };

        let nonce_len = 12;
        let nonce = GenericArray::from_slice(&input_base64decoded[0..nonce_len]);
        let ciphertext = &input_base64decoded[nonce_len..];

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid ChaCha20Poly1305 key")),
        };
        let decrypted = match cipher.decrypt(&nonce, ciphertext) {
            Ok(res) => res,
            Err(_) => return Err(String::from("ChaCha20Poly1305 failure to decrypt")),
        };
        Ok(decrypted.iter().map(|&i| i as char).collect())
    }
}

pub struct PGPEnDeCrypt {
    cert: Arc<Cert>,
    cert_passphrase: String,
}

impl PGPEnDeCrypt {
    pub fn new(cert: Arc<Cert>, cert_passphrase: &str) -> Self {
        let cert_passphrase = String::from(cert_passphrase);
        PGPEnDeCrypt {
            cert,
            cert_passphrase,
        }
    }
    pub fn new_no_certpass(cert: Arc<Cert>) -> Self {
        let cert_passphrase = String::from("");
        PGPEnDeCrypt {
            cert,
            cert_passphrase,
        }
    }
}

// Implement the Cryptical trait for PGPEnDeCrypt
impl Cryptical for PGPEnDeCrypt {
    fn get_public_key_as_base64(&self) -> String {
        pgp::get_public_key_as_base64(self.cert.clone())
    }
    fn get_public_key_fingerprint(&self) -> String {
        self.cert.fingerprint().to_string()
    }
}
impl CrypticalID for PGPEnDeCrypt {
    fn get_userid(&self) -> String {
        let mut userid = "".to_string();
        for uid in self.cert.userids() {
            userid.push_str(&uid.userid().to_string());
        }
        return userid;
    }
}

impl CrypticalEncrypt for PGPEnDeCrypt {
    fn encrypt(&self, input: &str) -> Result<String, String> {
        // Implement your encryption logic here
        let mut sink = Vec::new();
        let p = &P::new();
        match pgp::encrypt(p, &mut sink, input, self.cert.clone()) {
            Ok(_) => Ok(base64::encode(sink)),
            Err(_msg) => Err(String::from("Failed to encrypt")),
        }
    }
}
impl CrypticalDecrypt for PGPEnDeCrypt {
    fn decrypt(&self, input: &str) -> Result<String, String> {
        // Implement your decryption logic here
        let mut sink = Vec::new();
        let p = &P::new();
        let input_base64decoded = match base64::decode(input) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid base64 input")),
        };
        match pgp::decrypt(
            p,
            &mut sink,
            &input_base64decoded,
            self.cert.clone(),
            &self.cert_passphrase,
        ) {
            Ok(_) => Ok(String::from_utf8(sink).unwrap()),
            Err(_msg) => Err(String::from("Failed to decrypt")),
        }
    }
}

pub struct PGPEnCryptOwned {
    cert: Arc<Cert>,
}

impl PGPEnCryptOwned {
    pub fn new(cert: Cert) -> Self {
        PGPEnCryptOwned {
            cert: Arc::new(cert),
        }
    }
    pub fn new_from_str(cert_str: &str) -> Result<Self, String> {
        match pgp::read_from_str(cert_str) {
            Ok(cert) => Ok(PGPEnCryptOwned {
                cert: Arc::new(cert),
            }),
            Err(msg) => Err(msg),
        }
    }
    pub fn new_from_vec(cert_vec: &Vec<u8>) -> Result<Self, String> {
        match pgp::read_from_vec(cert_vec) {
            Ok(cert) => Ok(PGPEnCryptOwned {
                cert: Arc::new(cert),
            }),
            Err(msg) => Err(msg),
        }
    }
}

impl CrypticalID for PGPEnCryptOwned {
    fn get_userid(&self) -> String {
        let mut userid = "".to_string();
        for uid in self.cert.userids() {
            userid.push_str(&uid.userid().to_string());
        }
        return userid;
    }
}

impl CrypticalEncrypt for PGPEnCryptOwned {
    fn encrypt(&self, input: &str) -> Result<String, String> {
        // Implement your encryption logic here
        let mut sink = Vec::new();
        let p = &P::new();
        match pgp::encrypt(p, &mut sink, input, self.cert.clone()) {
            Ok(_) => Ok(base64::encode(sink)),
            Err(_msg) => Err(String::from("Failed to encrypt")),
        }
    }
}

// Implement the Cryptical trait for PGPEnDeCrypt
impl Cryptical for PGPEnCryptOwned {
    fn get_public_key_as_base64(&self) -> String {
        pgp::get_public_key_as_base64(self.cert.clone())
    }
    fn get_public_key_fingerprint(&self) -> String {
        self.cert.fingerprint().to_string()
    }
}

pub fn sha256sum(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text);
    base64::encode(hasher.finalize())
}
