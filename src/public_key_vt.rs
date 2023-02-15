use super::SecretKey;
use bls12_381_plus::{G1Affine, G1Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// A BLS public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyVt(pub G1Projective);

impl Default for PublicKeyVt {
    fn default() -> Self {
        Self(G1Projective::IDENTITY)
    }
}

impl Display for PublicKeyVt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&SecretKey> for PublicKeyVt {
    fn from(s: &SecretKey) -> Self {
        Self(G1Projective::GENERATOR * s.0)
    }
}

impl From<PublicKeyVt> for [u8; PublicKeyVt::BYTES] {
    fn from(pk: PublicKeyVt) -> Self {
        pk.to_bytes()
    }
}

impl<'a> From<&'a PublicKeyVt> for [u8; PublicKeyVt::BYTES] {
    fn from(pk: &'a PublicKeyVt) -> [u8; PublicKeyVt::BYTES] {
        pk.to_bytes()
    }
}

impl Serialize for PublicKeyVt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicKeyVt {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G1Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

cond_select_impl!(PublicKeyVt, G1Projective);

impl PublicKeyVt {
    /// Number of bytes needed to represent the public key
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);
}
