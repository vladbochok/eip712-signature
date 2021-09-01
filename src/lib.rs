//! This is implementation of a standard for hashing typed structured data for [EIP-712](https://eips.ethereum.org/EIPS/eip-712) signing standard.
//!
//! This module contains the necessary interfaces for obtaining a hash of the structure, which is later needed for EIP-712 signing.

mod member_types;
pub mod packed_signature;
pub mod struct_builder;
pub mod typed_structure;

pub use packed_signature::*;
pub use struct_builder::*;
pub use typed_structure::*;

pub use ethereum_types;
pub use parity_crypto;

#[cfg(test)]
mod tests;
