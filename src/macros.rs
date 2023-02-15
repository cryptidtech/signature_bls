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