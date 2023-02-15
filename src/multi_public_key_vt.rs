use crate::PublicKeyVt;
use bls12_381_plus::{G1Affine, G1Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiPublicKeyVt(pub G1Projective);

impl From<&[PublicKeyVt]> for MultiPublicKeyVt {
    fn from(keys: &[PublicKeyVt]) -> Self {
        let mut g = G1Projective::IDENTITY;
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

impl Display for MultiPublicKeyVt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for MultiPublicKeyVt {
    fn default() -> Self {
        Self(G1Projective::IDENTITY)
    }
}

impl Serialize for MultiPublicKeyVt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for MultiPublicKeyVt {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G1Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

impl subtle::ConditionallySelectable for MultiPublicKeyVt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(G1Projective::conditional_select(&a.0, &b.0, choice))
    }
}

impl MultiPublicKeyVt {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = 48;

    validity_checks!();

    /// Get the byte representation of this key
    pub fn to_bytes(self) -> [u8; Self::BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a big-endian representation of the multi public key
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        let mut t = [0u8; Self::BYTES];
        t.copy_from_slice(bytes);
        G1Affine::from_compressed(&t).map(|p| Self(G1Projective::from(&p)))
    }
}
