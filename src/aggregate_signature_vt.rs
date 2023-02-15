use crate::{PublicKeyVt, SignatureVt};
use bls12_381_plus::{G1Affine, G2Affine, G2Projective};
use core::fmt::{self, Display};
use group::{Curve, Group};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, CtOption};

/// Represents a BLS signature in G1 for multiple signatures that signed the different messages
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateSignatureVt(pub G2Projective);

impl Display for AggregateSignatureVt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for AggregateSignatureVt {
    fn default() -> Self {
        Self(G2Projective::IDENTITY)
    }
}

impl From<&[SignatureVt]> for AggregateSignatureVt {
    fn from(sigs: &[SignatureVt]) -> Self {
        let mut g = G2Projective::IDENTITY;
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

impl Serialize for AggregateSignatureVt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for AggregateSignatureVt {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G2Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

cond_select_impl!(AggregateSignatureVt, G2Projective);

impl AggregateSignatureVt {
    /// Number of bytes needed to represent the signature
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    /// Verify this multi signature is over `msg` with the multi public key
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKeyVt, B)]) -> Choice {
        if self.is_invalid().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }

        #[cfg(not(feature = "alloc"))]
        fn core_aggregate_verify<B: AsRef<[u8]>>(
            sig: &G2Projective,
            data: &[(PublicKeyVt, B)],
        ) -> Choice {
            use bls12_381_plus::{pairing, Gt};

            let mut res = Gt::IDENTITY;
            for (key, msg) in data {
                if key.is_invalid().unwrap_u8() == 1 {
                    return Choice::from(0u8);
                }
                let a = SignatureVt::hash_msg(msg.as_ref());
                res += pairing(&key.0.to_affine(), &a.to_affine());
            }
            res += pairing(&G1Affine::generator().neg(), &sig.to_affine());
            res.is_identity()
        }
        #[cfg(any(feature = "alloc", feature = "std"))]
        fn core_aggregate_verify<B: AsRef<[u8]>>(
            sig: &G2Projective,
            data: &[(PublicKeyVt, B)],
        ) -> Choice {
            use bls12_381_plus::{multi_miller_loop, G2Prepared};

            if data.iter().any(|(k, _)| k.is_invalid().unwrap_u8() == 1) {
                return Choice::from(0u8);
            }

            let mut data = data
                .iter()
                .map(|(key, m)| {
                    (
                        key.0.to_affine(),
                        G2Prepared::from(SignatureVt::hash_msg(m.as_ref()).to_affine()),
                    )
                })
                .collect::<Vec<(G1Affine, G2Prepared)>>();

            data.push((-G1Affine::generator(), G2Prepared::from(sig.to_affine())));
            // appease borrow checker
            let t = data
                .iter()
                .map(|(p1, p2)| (p1, p2))
                .collect::<Vec<(&G1Affine, &G2Prepared)>>();
            multi_miller_loop(t.as_slice())
                .final_exponentiation()
                .is_identity()
        }
        core_aggregate_verify(&self.0, data)
    }
}
