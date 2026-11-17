#![doc = include_str!("../README.md")]

use std::fmt;

use sha2::{Digest, Sha256};
use stellar_xdr::{ReadXdr, TransactionEnvelope, TransactionV1Envelope};

/// The XDR types used by this crate, including operation and authorization types.
pub use stellar_xdr as xdr;

/// Maximum decoded envelope size, in bytes.
pub const MAX_XDR_BYTES: usize = 128 * 1024;

/// Maximum base64 input size, including any whitespace.
pub const MAX_BASE64_BYTES: usize = MAX_XDR_BYTES.div_ceil(3) * 4;

/// Maximum nesting depth accepted by the XDR decoder.
pub const MAX_XDR_DEPTH: u32 = 32;

fn limits() -> xdr::Limits {
    xdr::Limits {
        depth: MAX_XDR_DEPTH,
        len: MAX_XDR_BYTES,
    }
}

/// A parsing or signing-digest verification failure.
#[derive(Debug)]
pub enum Error {
    /// Input exceeds the parser's size limit.
    InputTooLarge,
    /// The input cannot be decoded completely within the XDR limits.
    InvalidXdr(xdr::Error),
    /// Version 0 and fee-bump envelopes are outside this crate's initial scope.
    UnsupportedEnvelope,
    /// The supplied network passphrase is empty.
    EmptyNetworkPassphrase,
    /// The envelope's signing digest differs from the requested digest.
    SigningHashMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("transaction input exceeds the size limit"),
            Self::InvalidXdr(error) => write!(f, "invalid transaction XDR: {error}"),
            Self::UnsupportedEnvelope => {
                f.write_str("only version 1 transaction envelopes are supported")
            }
            Self::EmptyNetworkPassphrase => f.write_str("network passphrase must not be empty"),
            Self::SigningHashMismatch => {
                f.write_str("transaction does not match the requested signing digest")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidXdr(error) => Some(error),
            _ => None,
        }
    }
}

/// An immutable decoded envelope and its network-specific signing digest.
#[derive(Debug)]
pub struct ParsedTransaction {
    envelope: TransactionV1Envelope,
    signing_hash: [u8; 32],
}

/// One contract invocation, with its original authorization entries.
#[derive(Debug)]
pub struct ContractCall<'a> {
    /// Zero-based index in the transaction's complete operation list.
    pub operation_index: usize,
    /// Contract address, function name, and typed arguments.
    pub invocation: &'a xdr::InvokeContractArgs,
    /// Credentials and complete nested authorization trees, without flattening.
    pub authorizations: &'a [xdr::SorobanAuthorizationEntry],
}

impl ParsedTransaction {
    /// Returns the complete transaction, including source, fee in stroops,
    /// sequence, preconditions, memo, operations, and Soroban resource data.
    pub fn transaction(&self) -> &xdr::Transaction {
        &self.envelope.tx
    }

    /// Returns existing signatures without verifying them.
    pub fn signatures(&self) -> &[xdr::DecoratedSignature] {
        &self.envelope.signatures
    }

    /// Returns the network-specific digest to sign, excluding envelope signatures.
    pub fn signing_hash(&self) -> &[u8; 32] {
        &self.signing_hash
    }

    /// Checks the digest supplied by an authenticated signing request.
    ///
    /// This compares digests only; authenticating the request is the caller's job.
    pub fn verify_signing_hash(&self, expected: &[u8; 32]) -> Result<(), Error> {
        if self.signing_hash == *expected {
            Ok(())
        } else {
            Err(Error::SigningHashMismatch)
        }
    }

    /// Iterates over `InvokeContract` operations and their authorization entries.
    ///
    /// Other operations and host functions remain in [`Self::transaction`].
    /// Policies must inspect that complete operation list before approval.
    pub fn contract_calls(&self) -> impl Iterator<Item = ContractCall<'_>> {
        self.envelope
            .tx
            .operations
            .iter()
            .enumerate()
            .filter_map(|(operation_index, operation)| {
                let xdr::OperationBody::InvokeHostFunction(host) = &operation.body else {
                    return None;
                };
                let xdr::HostFunction::InvokeContract(invocation) = &host.host_function else {
                    return None;
                };
                Some(ContractCall {
                    operation_index,
                    invocation,
                    authorizations: &host.auth,
                })
            })
    }
}

/// Parses a complete binary XDR envelope using fixed byte and depth limits.
///
/// The caller supplies the exact network passphrase. Trailing bytes, unsupported
/// envelope types, and an empty network passphrase are rejected. Successful parsing
/// does not imply that the transaction is valid on the network or safe to approve.
pub fn parse_xdr(bytes: &[u8], network_passphrase: &str) -> Result<ParsedTransaction, Error> {
    validate_network(network_passphrase)?;
    if bytes.len() > MAX_XDR_BYTES {
        return Err(Error::InputTooLarge);
    }
    let envelope = TransactionEnvelope::from_xdr(bytes, limits()).map_err(Error::InvalidXdr)?;
    finish(envelope, network_passphrase)
}

/// Parses a complete base64 XDR envelope using fixed byte and depth limits.
///
/// ASCII whitespace is accepted by the XDR decoder and counts toward the input
/// size limit. The same envelope restrictions as [`parse_xdr`] apply.
pub fn parse_base64(input: &str, network_passphrase: &str) -> Result<ParsedTransaction, Error> {
    validate_network(network_passphrase)?;
    if input.len() > MAX_BASE64_BYTES {
        return Err(Error::InputTooLarge);
    }
    let envelope =
        TransactionEnvelope::from_xdr_base64(input, limits()).map_err(Error::InvalidXdr)?;
    finish(envelope, network_passphrase)
}

fn validate_network(network_passphrase: &str) -> Result<(), Error> {
    if network_passphrase.is_empty() {
        Err(Error::EmptyNetworkPassphrase)
    } else {
        Ok(())
    }
}

fn finish(
    envelope: TransactionEnvelope,
    network_passphrase: &str,
) -> Result<ParsedTransaction, Error> {
    let TransactionEnvelope::Tx(envelope) = envelope else {
        return Err(Error::UnsupportedEnvelope);
    };
    let network_id = Sha256::digest(network_passphrase.as_bytes()).into();
    let signing_hash = envelope.tx.hash(network_id).map_err(Error::InvalidXdr)?;
    Ok(ParsedTransaction {
        envelope,
        signing_hash,
    })
}
