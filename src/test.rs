use std::io::{self, Write};

use sequoia_openpgp as openpgp;

use crate::openpgp::cert::prelude::*;
use crate::openpgp::parse::{stream::*, Parse};
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;
use crate::openpgp::serialize::stream::*;

const MESSAGE: &str = "дружба";

mod pgp;
mod util;
use pgp::pgp::{
    generate_new_key, get_public_key_as_base64, read_from_gpg, read_from_vec, test_sign_verify,
};

fn main() -> openpgp::Result<()> {
    // Generate a key.
    let key = generate_new_key().unwrap();

    // Sign the message.
    let mut signed_message = Vec::new();
    sign(&mut signed_message, MESSAGE, &key)?;

    // Verify the message.
    let mut plaintext = Vec::new();
    verify(&mut plaintext, &signed_message, &key)?;

    if MESSAGE.as_bytes() == &plaintext[..] {
        println!("YES");
    } else {
        println!("NO");
    }

    Ok(())
}

/// Generates an signing-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(cert)
}

/// Signs the given message.
fn sign(
    sink: &mut (dyn Write + Send + Sync),
    plaintext: &str,
    tsk: &openpgp::Cert,
) -> openpgp::Result<()> {
    let p = &P::new();
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk
        .keys()
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
        .into_keypair()?;

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to sign a literal data packet.
    let signer = Signer::new(message, keypair).build()?;

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(signer).build()?;

    // Sign the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

/// Verifies the given message.
fn verify(
    sink: &mut dyn Write,
    signed_message: &[u8],
    sender: &openpgp::Cert,
) -> openpgp::Result<()> {
    // Make a helper that that feeds the sender's public key to the
    // verifier.
    //
    let p = &P::new();
    let helper = Helper { cert: sender };

    // Now, create a verifier with a helper using the given Certs.
    let mut verifier = VerifierBuilder::from_bytes(signed_message)?.with_policy(p, None, helper)?;

    // Verify the data.
    io::copy(&mut verifier, sink)?;

    Ok(())
}

struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
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
                (0, MessageLayer::SignatureGroup { results }) => {
                    // Finally, given a VerificationResult, which only says
                    // whether the signature checks out mathematically, we apply
                    // our policy.
                    match results.into_iter().next() {
                        Some(Ok(_)) => good = true,
                        Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
                        None => return Err(anyhow::anyhow!("No signature")),
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        if good {
            Ok(()) // Good signature.
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}
