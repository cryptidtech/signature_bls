use crate::PublicKey;
use bls12_381_plus::{G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiPublicKey(pub G2Projective);

impl From<&[PublicKey]> for MultiPublicKey {
    fn from(keys: &[PublicKey]) -> Self {
        let mut g = G2Projective::IDENTITY;
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

impl Display for MultiPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for MultiPublicKey {
    fn default() -> Self {
        Self(G2Projective::IDENTITY)
    }
}

impl Serialize for MultiPublicKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for MultiPublicKey {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G2Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

impl subtle::ConditionallySelectable for MultiPublicKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(G2Projective::conditional_select(&a.0, &b.0, choice))
    }
}

impl MultiPublicKey {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = 96;

    validity_checks!();

    /// Get the byte representation of this key
    pub fn to_bytes(self) -> [u8; Self::BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a big-endian representation of the multi public key
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        let mut t = [0u8; Self::BYTES];
        t.copy_from_slice(bytes);
        G2Affine::from_compressed(&t).map(|p| Self(G2Projective::from(&p)))
    }
}
