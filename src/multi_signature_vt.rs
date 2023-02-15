use crate::{MultiPublicKeyVt, PublicKeyVt, SignatureVt};
use bls12_381_plus::{G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents a BLS SignatureVt in G1 for multiple SignatureVts that signed the same message
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiSignatureVt(pub G2Projective);

impl Default for MultiSignatureVt {
    fn default() -> Self {
        Self(G2Projective::IDENTITY)
    }
}

impl Display for MultiSignatureVt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&[SignatureVt]> for MultiSignatureVt {
    fn from(sigs: &[SignatureVt]) -> Self {
        let mut g = G2Projective::IDENTITY;
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

impl Serialize for MultiSignatureVt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for MultiSignatureVt {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G2Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

impl subtle::ConditionallySelectable for MultiSignatureVt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(G2Projective::conditional_select(&a.0, &b.0, choice))
    }
}

impl MultiSignatureVt {
    /// Number of bytes needed to represent the SignatureVt
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    /// Verify this multi SignatureVt is over `msg` with the multi public key
    pub fn verify<B: AsRef<[u8]>>(&self, public_key: MultiPublicKeyVt, msg: B) -> Choice {
        SignatureVt(self.0).verify(PublicKeyVt(public_key.0), msg)
    }
}
