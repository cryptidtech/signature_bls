use super::SecretKey;
use bls12_381_plus::{G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::Curve;
use subtle::{Choice, CtOption};

/// A BLS public key
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(s: &SecretKey) -> Self {
        Self(G2Projective::GENERATOR * s.0)
    }
}

impl From<PublicKey> for [u8; PublicKey::BYTES] {
    fn from(pk: PublicKey) -> Self {
        pk.to_bytes()
    }
}

impl<'a> From<&'a PublicKey> for [u8; PublicKey::BYTES] {
    fn from(pk: &'a PublicKey) -> [u8; PublicKey::BYTES] {
        pk.to_bytes()
    }
}

serde_impl!(PublicKey, G2Projective);

cond_select_impl!(PublicKey, G2Projective);

impl PublicKey {
    /// Number of bytes needed to represent the public key
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);
}
