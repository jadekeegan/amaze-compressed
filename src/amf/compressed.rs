#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};

use crate::{
    amf::{AMFInternalSignature, AMFSignature},
    pok::{chaum_pedersen::ChaumPedersenProverCommitment, or_proof::OrProverResponse},
};

#[derive(Debug, Copy, Clone)]
pub struct CompressedChaumPedersenProverCommitment {
    v_t: CompressedRistretto,
    w_t: CompressedRistretto,
}
impl From<ChaumPedersenProverCommitment> for CompressedChaumPedersenProverCommitment {
    fn from(commitment: ChaumPedersenProverCommitment) -> Self {
        CompressedChaumPedersenProverCommitment {
            v_t: commitment.v_t.compress(),
            w_t: commitment.w_t.compress(),
        }
    }
}
impl From<CompressedChaumPedersenProverCommitment> for ChaumPedersenProverCommitment {
    fn from(compressed_commitment: CompressedChaumPedersenProverCommitment) -> Self {
        ChaumPedersenProverCommitment {
            v_t: compressed_commitment.v_t.decompress().unwrap(),
            w_t: compressed_commitment.w_t.decompress().unwrap(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CompressedAMFInternalSignature {
    or_prover_commitment_0: (CompressedRistretto, CompressedRistretto),
    or_prover_commitment_1: (CompressedChaumPedersenProverCommitment, CompressedRistretto),
    or_prover_response_0: OrProverResponse<Scalar, Scalar>,
    or_prover_response_1: OrProverResponse<Scalar, Scalar>,
}
impl From<AMFInternalSignature> for CompressedAMFInternalSignature {
    fn from(signature: AMFInternalSignature) -> Self {
        CompressedAMFInternalSignature {
            or_prover_commitment_0: (
                signature.prover_commitment.0 .0.compress(),
                signature.prover_commitment.0 .1.compress(),
            ),
            or_prover_commitment_1: (
                signature.prover_commitment.1 .0.into(),
                signature.prover_commitment.1 .1.compress(),
            ),
            or_prover_response_0: signature.prover_response.0,
            or_prover_response_1: signature.prover_response.1,
        }
    }
}
impl From<CompressedAMFInternalSignature> for AMFInternalSignature {
    fn from(compressed_signature: CompressedAMFInternalSignature) -> Self {
        AMFInternalSignature {
            prover_commitment: (
                (
                    compressed_signature
                        .or_prover_commitment_0
                        .0
                        .decompress()
                        .unwrap(),
                    compressed_signature
                        .or_prover_commitment_0
                        .1
                        .decompress()
                        .unwrap(),
                ),
                (
                    compressed_signature.or_prover_commitment_1.0.into(),
                    compressed_signature
                        .or_prover_commitment_1
                        .1
                        .decompress()
                        .unwrap(),
                ),
            ),
            prover_response: (
                compressed_signature.or_prover_response_0,
                compressed_signature.or_prover_response_1,
            ),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CompressedAMFSignature {
    pub pi: CompressedAMFInternalSignature,
    pub J: CompressedRistretto,
    pub R: CompressedRistretto,
    pub E_J: CompressedRistretto,
    pub E_R: CompressedRistretto,
}
impl From<AMFSignature> for CompressedAMFSignature {
    fn from(signature: AMFSignature) -> Self {
        CompressedAMFSignature {
            pi: signature.pi.into(),
            J: signature.J.compress(),
            R: signature.R.compress(),
            E_J: signature.E_J.compress(),
            E_R: signature.E_R.compress(),
        }
    }
}
impl From<CompressedAMFSignature> for AMFSignature {
    fn from(compressed_signature: CompressedAMFSignature) -> Self {
        AMFSignature {
            pi: compressed_signature.pi.into(),
            J: compressed_signature.J.decompress().unwrap(),
            R: compressed_signature.R.decompress().unwrap(),
            E_J: compressed_signature.E_J.decompress().unwrap(),
            E_R: compressed_signature.E_R.decompress().unwrap(),
        }
    }
}
