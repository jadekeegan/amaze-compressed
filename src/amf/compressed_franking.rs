//! AMF Franking Algorithms (KeyGen, Frank, Verify, Judge)
//!
//! Cf. Fig. 5 in [AMF]
//!
//! [AMF]: https://eprint.iacr.org/2019/565/20190527:092413
#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable, scalar::Scalar,
};

use crate::{
    amf::{compressed::CompressedAMFSignature, AMFPublicKey, AMFRole, AMFSecretKey, AMFSignature},
    pok::{
        fiat_shamir::{FiatShamirSecretKey, SignatureScheme},
        or_proof::OrWitness,
    },
};

use super::spok_amf::AMFSPoK;

pub fn keygen(role: AMFRole) -> (AMFPublicKey, AMFSecretKey) {
    // cf. Fig. 5 in [AMF]
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    let secret_key = Scalar::random(&mut rng);
    let public_key = secret_key * g;
    (
        AMFPublicKey { role, public_key },
        AMFSecretKey { role, secret_key },
    )
}

pub fn frank(
    sender_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    message: &[u8],
) -> CompressedAMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);

    let J = alpha * judge_public_key.public_key;
    let R = beta * recipient_public_key.public_key;
    let E_J = alpha * g;
    let E_R = beta * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        J,
        R,
        E_J,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: false,
                    s0_witness: Some(sender_secret_key.secret_key),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    CompressedAMFSignature::from(AMFSignature { pi, J, R, E_J, E_R })
}

pub fn verify(
    recipient_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    message: &[u8],
    compressed_amf_signature: CompressedAMFSignature,
) -> bool {
    let amf_signature = AMFSignature::from(compressed_amf_signature);

    let b1 = amf_signature.R == recipient_secret_key.secret_key * amf_signature.E_R;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        amf_signature.J,
        amf_signature.R,
        amf_signature.E_J,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn judge(
    judge_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    message: &[u8],
    compressed_amf_signature: CompressedAMFSignature,
) -> bool {
    let amf_signature = AMFSignature::from(compressed_amf_signature);

    let b1 = amf_signature.J == judge_secret_key.secret_key * amf_signature.E_J;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        amf_signature.J,
        amf_signature.R,
        amf_signature.E_J,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_franking() {
        // 0. Initialize a Sender
        let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
        // 1. Initialize a Recipient
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        // 2. Initialize a Judge
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);

        // 3. Initialize a message
        let message = b"hello world!";

        // 4. Frank the message
        let amf_signature = frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            message,
        );

        // 5. Verify the message
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        // 6. Judge the message
        let judging_result = judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result);
    }
}
