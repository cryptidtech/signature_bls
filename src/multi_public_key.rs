use crate::PublicKey;
use bls12_381_plus::{G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::Curve;
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

serde_impl!(MultiPublicKey, G2Projective);

cond_select_impl!(MultiPublicKey, G2Projective);

impl MultiPublicKey {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);
}
