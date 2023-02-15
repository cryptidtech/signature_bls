use crate::{MultiPublicKey, PublicKey, Signature};
use bls12_381_plus::{G1Affine, G1Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents a BLS signature in G1 for multiple signatures that signed the same message
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiSignature(pub G1Projective);

impl Display for MultiSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&[Signature]> for MultiSignature {
    fn from(sigs: &[Signature]) -> Self {
        let mut g = G1Projective::IDENTITY;
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

impl Serialize for MultiSignature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for MultiSignature {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G1Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

cond_select_impl!(MultiSignature, G1Projective);

impl MultiSignature {
    /// Number of bytes needed to represent the signature
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    /// Verify this multi signature is over `msg` with the multi public key
    pub fn verify<B: AsRef<[u8]>>(&self, public_key: MultiPublicKey, msg: B) -> Choice {
        Signature(self.0).verify(PublicKey(public_key.0), msg)
    }
}
