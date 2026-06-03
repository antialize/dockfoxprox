//! A 32-byte SHA-256 digest with `"sha256:<hex>"` text representation.
//!
//! Docker references digests as `sha256:<64 hex chars>`; we store them as the
//! raw 32-byte array to make hashing and equality cheap, and reconstruct the
//! text form on demand for HTTP headers and log lines.

/// A 32-byte SHA-256 digest. Displays as `"sha256:<hex>"`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Digest(pub [u8; 32]);

impl std::str::FromStr for Digest {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix("sha256:").ok_or(())?;
        if hex.len() != 64 {
            return Err(());
        }
        let bytes = hex.as_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = (bytes[2 * i] as char).to_digit(16).ok_or(())? as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).ok_or(())? as u8;
            out[i] = (hi << 4) | lo;
        }
        Ok(Digest(out))
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sha256:")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
