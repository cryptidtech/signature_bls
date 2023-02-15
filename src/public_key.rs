use super::SecretKey;
use bls12_381_plus::{G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// A BLS public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

impl Default for PublicKey {
    fn default() -> Self {
        Self(G2Projective::IDENTITY)
    }
}

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

impl Serialize for PublicKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G2Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

cond_select_impl!(PublicKey, G2Projective);

impl PublicKey {
    /// Number of bytes needed to represent the public key
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);
}
