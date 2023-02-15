macro_rules! validity_checks {
    () => {
        /// Check if this is valid
        pub fn is_valid(&self) -> Choice {
            !self.0.is_identity() | !self.0.is_on_curve()
        }

        /// Check if this is invalid
        pub fn is_invalid(&self) -> Choice {
            self.0.is_identity() | !self.0.is_on_curve()
        }
    };
}

macro_rules! bytes_impl {
    ($affine:ident, $projective:ident) => {
        /// Get the byte representation
        pub fn to_bytes(self) -> [u8; Self::BYTES] {
            self.0.to_affine().to_compressed()
        }

        /// Convert a big-endian representation
        pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
            $affine::from_compressed(bytes).map(|p| Self($projective::from(&p)))
        }
    };
}

macro_rules! cond_select_impl {
    ($name:ident, $projective:ident) => {
        impl subtle::ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self($projective::conditional_select(&a.0, &b.0, choice))
            }
        }
    };
}
