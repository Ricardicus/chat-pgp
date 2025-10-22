extern crate sequoia_openpgp as openpgp;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use openpgp::policy::StandardPolicy as P;
use openpgp::Cert;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::{engine::general_purpose as b64, Engine as _};
use libsodium_rs::{crypto_aead::xchacha20poly1305 as aead, crypto_kx};
use std::fmt::Write;

use std::fs::OpenOptions;
use std::io::Write as IoWrite;

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
pub trait CrypticalSign {
    fn sign(&self, input: &str) -> Result<String, String>;
}
pub trait CrypticalVerify {
    fn verify(&self, signature: &str, value: &str) -> Result<bool, String>;
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
impl Cryptical for PGPEnCryptOwned {
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
impl CrypticalID for &PGPEnCryptOwned {
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
impl Cryptical for &PGPEnCryptOwned {
    fn get_public_key_as_base64(&self) -> String {
        pgp::get_public_key_as_base64(self.cert.clone())
    }
    fn get_public_key_fingerprint(&self) -> String {
        self.cert.fingerprint().to_string()
    }
}

impl CrypticalSign for PGPEnDeCrypt {
    fn sign(&self, input: &str) -> Result<String, String> {
        // Implement your signing logic here
        let mut sink = Vec::new();
        match pgp::sign(&mut sink, input, &self.cert.clone(), &self.cert_passphrase) {
            Ok(_) => {
                let s = base64::encode(sink);
                Ok(s)
            }
            Err(_msg) => Err(String::from("Failed to sign")),
        }
    }
}

impl CrypticalVerify for PGPEnDeCrypt {
    fn verify(&self, signature: &str, content: &str) -> Result<bool, String> {
        // Implement your verification logic here
        let signature_base64decoded = match base64::decode(signature) {
            Ok(res) => res,
            Err(_) => return Err(String::from("Invalid base64 input")),
        };
        match pgp::verify(&signature_base64decoded, &content, &self.cert.clone()) {
            Ok(()) => Ok(true),
            Err(_msg) => Err(String::from("Failed to verify")),
        }
    }
}

impl CrypticalVerify for PGPEnCryptOwned {
    fn verify(&self, signature: &str, content: &str) -> Result<bool, String> {
        // Implement your verification logic here
        let signature_base64decoded = match base64::decode(signature) {
            Ok(res) => res,
            Err(_) => {
                return Err(String::from("Invalid base64 input"));
            }
        };
        match pgp::verify(&signature_base64decoded, &content, &self.cert.clone()) {
            Ok(()) => Ok(true),
            Err(_msg) => Err(String::from("Failed to verify")),
        }
    }
}

pub fn sha256sum(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text);
    base64::encode(hasher.finalize())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SodiumKxEnDeCrypt {
    peer_pk_b64: String,
    tx_key_b64: String,
    rx_key_b64: String,
    my_pk_bytes: [u8; 32],
    pub decrypt_tx: bool,
}

impl SodiumKxEnDeCrypt {
    /// Create a session from your keypair and the peer's Base64 public key.
    /// `is_client = true` for client side; `false` for server side.
    pub fn new_from_keypair(
        my_kx: &crypto_kx::KeyPair,
        peer_pk_b64: &str,
        is_client: bool,
    ) -> Result<Self, String> {
        // Decode peer pubkey
        let peer_pk_vec = b64::STANDARD_NO_PAD
            .decode(peer_pk_b64)
            .or_else(|_| b64::STANDARD.decode(peer_pk_b64))
            .map_err(|_| "invalid base64: peer_pk_b64")?;

        if peer_pk_vec.len() != 32 {
            return Err("peer_pk must be 32 bytes".into());
        }

        let mut peer_pk_arr = [0u8; 32];
        peer_pk_arr.copy_from_slice(&peer_pk_vec);
        let peer_pk = crypto_kx::PublicKey::from_bytes(&peer_pk_arr)
            .map_err(|_| "peer public key invalid")?;

        // Correct DH direction
        let sess = if is_client {
            crypto_kx::client_session_keys(&my_kx.public_key, &my_kx.secret_key, &peer_pk)
        } else {
            crypto_kx::server_session_keys(&my_kx.public_key, &my_kx.secret_key, &peer_pk)
        }
        .map_err(|_| "session key derivation failed")?;

        let tx_key_b64 = b64::STANDARD_NO_PAD.encode(sess.tx);
        let rx_key_b64 = b64::STANDARD_NO_PAD.encode(sess.rx);

        let mut my_pk_bytes = [0u8; 32];
        my_pk_bytes.copy_from_slice(my_kx.public_key.as_bytes());

        Ok(Self {
            peer_pk_b64: peer_pk_b64.to_owned(),
            tx_key_b64,
            rx_key_b64,
            my_pk_bytes,
            decrypt_tx: false,
        })
    }

    pub fn my_public_key_b64(&self) -> String {
        b64::STANDARD_NO_PAD.encode(&self.my_pk_bytes)
    }

    pub fn tx_key_b64(&self) -> &str {
        &self.tx_key_b64
    }

    pub fn rx_key_b64(&self) -> &str {
        &self.rx_key_b64
    }

    fn tx_key(&self) -> Result<aead::Key, String> {
        let bytes = b64::STANDARD_NO_PAD
            .decode(&self.tx_key_b64)
            .or_else(|_| b64::STANDARD.decode(&self.tx_key_b64))
            .map_err(|_| "invalid tx_key base64".to_string())?;
        Ok(aead::Key::from_bytes(&bytes).map_err(|_| "invalid tx_key bytes".to_string())?)
    }

    fn rx_key(&self) -> Result<aead::Key, String> {
        let bytes = b64::STANDARD_NO_PAD
            .decode(&self.rx_key_b64)
            .or_else(|_| b64::STANDARD.decode(&self.rx_key_b64))
            .map_err(|_| "invalid rx_key base64".to_string())?;
        Ok(aead::Key::from_bytes(&bytes).map_err(|_| "invalid rx_key bytes".to_string())?)
    }

    /// Serialize this struct to CBOR bytes, then Base64 (no padding) as String.
    pub fn to_base64_cbor(&self) -> Result<String, String> {
        let cbor = serde_cbor::to_vec(self).map_err(|e| format!("CBOR encode error: {e}"))?;
        Ok(STANDARD_NO_PAD.encode(cbor))
    }

    /// Parse a Base64 (no-pad or padded) String, then CBOR-decode into Self.
    pub fn from_base64_cbor(s: &str) -> Result<Self, String> {
        let bytes = STANDARD_NO_PAD
            .decode(s)
            .or_else(|_| STANDARD.decode(s))
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        serde_cbor::from_slice(&bytes).map_err(|e| format!("CBOR decode error: {e}"))
    }
}

// === Traits ===

impl Cryptical for SodiumKxEnDeCrypt {
    fn get_public_key_as_base64(&self) -> String {
        self.my_public_key_b64()
    }

    fn get_public_key_fingerprint(&self) -> String {
        let bytes = &self.my_pk_bytes;
        let mut s = String::with_capacity(2 * 8 + 1 + 2 * 4);
        for b in &bytes[..8] {
            let _ = write!(s, "{:02x}", b);
        }
        s.push('…');
        for b in &bytes[28..] {
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

impl CrypticalEncrypt for SodiumKxEnDeCrypt {
    fn encrypt(&self, input: &str) -> Result<String, String> {
        let key = self.tx_key()?;
        let nonce = aead::Nonce::generate();
        let ct = aead::encrypt(input.as_bytes(), None, &nonce, &key)
            .map_err(|_| "aead encrypt failed".to_string())?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&ct);

        Ok(b64::STANDARD_NO_PAD.encode(&out))
    }
}

impl CrypticalDecrypt for SodiumKxEnDeCrypt {
    fn decrypt(&self, input: &str) -> Result<String, String> {
        let buf = b64::STANDARD_NO_PAD
            .decode(input)
            .or_else(|_| b64::STANDARD.decode(input))
            .map_err(|_| "bad base64 input".to_string())?;

        if buf.len() < 24 {
            return Err("ciphertext too short".into());
        }

        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(&buf[..24]);
        let nonce = aead::Nonce::from_bytes(nonce_arr);
        let ct = &buf[24..];

        let mut key = self.rx_key()?;
        if self.decrypt_tx {
            key = self.tx_key()?;
        }
        let pt =
            aead::decrypt(ct, None, &nonce, &key).map_err(|_| "aead decrypt failed".to_string())?;

        Ok(String::from_utf8(pt).map_err(|_| "utf8 error".to_string())?)
    }
}
