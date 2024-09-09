pub mod pgp {

    use crate::util::execute_command;
    extern crate sequoia_openpgp as openpgp;

    use openpgp::cert::prelude::*;
    use openpgp::crypto::Password;
    use std::io::{self, Write};
    use std::sync::Arc;

    use openpgp::crypto::SessionKey;
    use openpgp::parse::stream::MessageLayer;
    use openpgp::parse::{stream::*, Parse};
    use openpgp::policy::Policy;
    use openpgp::policy::StandardPolicy as P;
    use openpgp::serialize::stream::*;
    use openpgp::serialize::Serialize;
    use openpgp::types::KeyFlags;
    use openpgp::types::SymmetricAlgorithm;

    pub fn read_from_str(cert: &str) -> Result<openpgp::Cert, String> {
        let cert = openpgp::Cert::from_bytes(cert.as_bytes());
        if cert.is_ok() {
            Ok(cert.unwrap())
        } else {
            Err("Failed to read the key".to_string())
        }
    }

    pub fn read_from_vec(cert: &Vec<u8>) -> Result<openpgp::Cert, String> {
        let cert = openpgp::Cert::from_bytes(cert);
        if cert.is_ok() {
            Ok(cert.unwrap())
        } else {
            Err("Failed to read the key".to_string())
        }
    }

    pub fn generate_new_key() -> Result<openpgp::Cert, String> {
        let res = CertBuilder::general_purpose(None, Some("chatpgp@example.org"))
            .set_cipher_suite(CipherSuite::RSA2k)
            .generate();
        if res.is_err() {
            return Err("Failed to generate a new key".to_string());
        }
        let (rsa_cert, _) = res.unwrap();
        Ok(rsa_cert)
    }

    pub fn read_from_gpg(gpgkey: &str, passphrase: Option<&str>) -> Result<openpgp::Cert, String> {
        let res = match passphrase {
            Some(pass) => execute_command(&format!(
                "gpg --batch --pinentry-mode loopback --passphrase {} --export-secret-key -a {}",
                pass, gpgkey
            )),
            None => execute_command(&format!("gpg --export-secret-key -a {}", gpgkey)),
        };

        match res.as_ref().err() {
            Some(error_msg) => {
                return Err(format!("error: Failed to read the gpg key: {}", error_msg));
            }
            None => {}
        }
        let cert = openpgp::Cert::from_bytes(res.expect("uknown error").as_bytes());
        if cert.is_ok() {
            Ok(cert.unwrap())
        } else {
            Err("Failed to read the key".to_string())
        }
    }

    pub fn test_sign_verify(cert: &openpgp::Cert) -> bool {
        let mut v = Vec::new();
        let text = "hello".to_string();
        let passphrase = "1234512345".to_string();

        sign(&mut v, &text, cert, &passphrase);

        //let val = v;// base64::encode(v);

        //let val = val; //base64::decode(val).unwrap();
        let val = v;
        match verify(&val, &text, &cert) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn sign(
        sink: &mut (dyn Write + Send + Sync),
        plaintext: &str,
        tsk: &openpgp::Cert,
        passphrase: &str,
    ) -> openpgp::Result<()> {
        let p = &P::new();
        // Get the keypair to do the signing from the Cert.
        let key = tsk.primary_key().key().clone().parts_into_secret()?;
        let mut keypair = None;
        if passphrase.len() == 0 {
            keypair = Some(
                tsk.keys()
                    .unencrypted_secret()
                    .with_policy(p, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_signing()
                    .next()
                    .unwrap()
                    .key()
                    .clone()
                    .into_keypair()?,
            );
        } else {
            let passphrase: Password = String::from(passphrase).into();
            for key in tsk.keys() {
                match key
                    .key()
                    .clone()
                    .parts_into_secret()
                    .unwrap()
                    .decrypt_secret(&passphrase)
                {
                    Ok(k) => {
                        keypair = Some(k.into_keypair().unwrap());
                        break;
                    }
                    Err(_) => {
                        keypair = Some(
                            key.key()
                                .clone()
                                .parts_into_secret()
                                .unwrap()
                                .into_keypair()
                                .unwrap(),
                        );
                    }
                }
            }
        }

        let keypair = keypair.unwrap();

        // Start streaming an OpenPGP message.
        let message = Message::new(sink);

        // We want to sign a literal data packet.
        let message = Signer::new(message, keypair).build()?;

        // Emit a literal data packet.
        let mut message = LiteralWriter::new(message).build()?;

        // Sign the data.
        message.write_all(plaintext.clone().as_bytes())?;

        // Finalize the OpenPGP message to make sure that all data is
        // written.
        message.finalize()?;

        Ok(())
    }

    pub fn get_public_key_as_base64(cert: Arc<Cert>) -> String {
        // Serializing a `Key<key::PublicParts, _>` drops the secret key
        // material.
        let mut bytes = Vec::new();
        let _ = cert.clone().serialize(&mut bytes);
        base64::encode(bytes)
    }

    /// Verifies the given message.
    pub fn verify(
        signed_message: &[u8],
        signed_content: &str,
        sender: &openpgp::Cert,
    ) -> openpgp::Result<()> {
        let p = &P::new();
        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: sender };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier =
            VerifierBuilder::from_bytes(signed_message)?.with_policy(p, None, helper)?;
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink)?;

        let message_content = String::from_utf8(sink).unwrap();
        if message_content != signed_content.to_string() {
            return Err(anyhow::anyhow!("Invalid message signature content"));
        }

        Ok(())
    }

    struct Helper<'a> {
        cert: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<openpgp::Cert>> {
            // Return public keys for signature verification here.
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            // In this function, we implement our signature verification
            // policy.

            let mut good = false;
            for (i, layer) in structure.into_iter().enumerate() {
                match (i, layer) {
                    // First, we are interested in signatures over the
                    // data, i.e. level 0 signatures.
                    (_, MessageLayer::SignatureGroup { results }) => {
                        // Finally, given a VerificationResult, which only says
                        // whether the signature checks out mathematically, we apply
                        // our policy.
                        match results.into_iter().next() {
                            Some(Ok(_)) => {
                                good = true;
                            }
                            Some(Err(e)) => {
                                return Err(openpgp::Error::from(e).into());
                            }
                            None => {
                                return Err(anyhow::anyhow!("No signature"));
                            }
                        }
                    }
                    (_o, _b) => {
                        // pass
                    }
                }
            }

            if good {
                Ok(()) // Good signature.
            } else {
                Err(anyhow::anyhow!("Signature verification failed"))
            }
        }
    }

    pub fn encrypt(
        policy: &dyn Policy,
        sink: &mut (dyn Write + Send + Sync),
        plaintext: &str,
        recipient: Arc<openpgp::Cert>,
    ) -> openpgp::Result<()> {
        let recipients = recipient
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption();

        // Start streaming an OpenPGP message.
        let message = Message::new(sink);

        let message = Armorer::new(message).build()?;

        // We want to encrypt a literal data packet.
        let message = Encryptor2::for_recipients(message, recipients).build()?;

        // Emit a literal data packet.
        let mut message = LiteralWriter::new(message).build()?;

        // Encrypt the data.
        message.write_all(plaintext.as_bytes())?;

        // Finalize the OpenPGP message to make sure that all data is
        // written.
        message.finalize()?;

        Ok(())
    }

    pub fn decrypt(
        policy: &dyn Policy,
        sink: &mut dyn Write,
        ciphertext: &[u8],
        cert: Arc<openpgp::Cert>,
        cert_passphrase: &str,
    ) -> openpgp::Result<()> {
        // Make a helper that that feeds the recipient's secret key to the
        // decryptor.
        let helper = DeHelper::new(cert, cert_passphrase);

        // Now, create a decryptor with a helper using the given Certs.
        let mut decryptor =
            DecryptorBuilder::from_bytes(ciphertext)?.with_policy(policy, None, helper)?;

        // Decrypt the data.
        io::copy(&mut decryptor, sink)?;

        Ok(())
    }

    struct DeHelper {
        cert: Arc<openpgp::Cert>,
        passphrase: Password,
    }

    impl DeHelper {
        /// Creates a Helper for the given Certs with appropriate secrets.
        fn new(cert: Arc<openpgp::Cert>, passphrase: &str) -> Self {
            // Map (sub)KeyIDs to primary fingerprints and secrets.
            let passphrase: Password = String::from(passphrase).into();
            DeHelper { cert, passphrase }
        }
    }

    impl DecryptionHelper for DeHelper {
        fn decrypt<D>(
            &mut self,
            pkesks: &[openpgp::packet::PKESK],
            _skesks: &[openpgp::packet::SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            mut decrypt: D,
        ) -> openpgp::Result<Option<openpgp::Fingerprint>>
        where
            D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
        {
            let _p = &P::new();
            let _mode = KeyFlags::empty().set_storage_encryption();
            // Try each PKESK until we succeed.
            let mut recipient = None;

            for key in self.cert.keys() {
                let mut keypair;
                match key
                    .key()
                    .clone()
                    .parts_into_secret()
                    .unwrap()
                    .decrypt_secret(&self.passphrase)
                {
                    Ok(k) => {
                        keypair = k.into_keypair().unwrap();
                    }
                    Err(_) => {
                        keypair = key
                            .key()
                            .clone()
                            .parts_into_secret()
                            .unwrap()
                            .into_keypair()
                            .unwrap();
                    }
                }

                for pkesk in pkesks {
                    if pkesk
                        .decrypt(&mut keypair, sym_algo)
                        .map(|(algo, session_key)| decrypt(algo, &session_key))
                        .unwrap_or(false)
                    {
                        recipient = Some(self.cert.fingerprint());
                        break;
                    } else {
                    }
                }
            }

            Ok(recipient)
        }
    }

    impl VerificationHelper for DeHelper {
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(Vec::new()) // Feed the Certs to the verifier here.
        }
        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            for layer in structure.iter() {
                match layer {
                    MessageLayer::Compression { algo } => eprintln!("Compressed using {}", algo),
                    MessageLayer::Encryption {
                        sym_algo: _,
                        aead_algo,
                    } => {
                        if let Some(_aead_algo) = aead_algo {
                            //eprintln!("Encrypted and protected using {}/{}", sym_algo, aead_algo);
                        } else {
                            //eprintln!("Encrypted using {}", sym_algo);
                        }
                    }
                    MessageLayer::SignatureGroup { ref results } => {
                        for result in results {
                            match result {
                                Ok(GoodChecksum { ka: _, .. }) => {
                                    //eprintln!("Good signature from {}", ka.cert());
                                }
                                Err(e) => eprintln!("Error: {:?}", e),
                            }
                        }
                    }
                }
            }
            Ok(()) // Implement your verification policy here.
        }
    }
}
