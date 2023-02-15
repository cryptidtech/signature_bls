use crate::PublicKeyVt;
use bls12_381_plus::{G1Affine, G1Projective};
use core::fmt::{self, Display};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

cond_select_impl!(MultiPublicKeyVt, G1Projective);

impl MultiPublicKeyVt {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);
}
