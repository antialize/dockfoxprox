//! Byte size with human-readable parse and display.
//!
//! Used in the config (`memory_limit`, `disk_limit`) to accept strings like
//! `"16GB"` and in `/metrics` formatting. Multipliers are binary (1 KB = 1024
//! B) despite the SI-style unit names.

use serde::Deserialize;
use thiserror::Error;

/// A byte count. Construct via `Size::from_str`, serde, or directly.
pub struct Size(pub u64);

impl std::fmt::Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut size = self.0 as f64;
        let units = ["B", "KB", "MB", "GB", "TB"];
        let mut unit = 0;
        while size >= 1024.0 && unit < units.len() - 1 {
            size /= 1024.0;
            unit += 1;
        }
        write!(f, "{:.2} {}", size, units[unit])
    }
}

#[derive(Error, Debug)]
pub enum ParseSizeError {
    #[error("invalid number: {0}")]
    InvalidNumber(#[from] std::num::ParseFloatError),
    #[error("invalid unit: {0}")]
    InvalidUnit(String),
}

impl Size {
    /// Parse a human-readable size string like `"100"`, `"512 KB"`, `"16GB"`.
    /// Bare numbers are bytes; recognised units are `B|KB|MB|GB|TB`
    /// (case-insensitive, all binary multipliers).
    pub fn from_str(s: &str) -> Result<Self, ParseSizeError> {
        let s = s.trim();
        let mut num_str = String::new();
        let mut unit_str = String::new();
        for c in s.chars() {
            if c.is_ascii_digit() || c == '.' {
                num_str.push(c);
            } else if !c.is_whitespace() {
                unit_str.push(c);
            }
        }
        let num: f64 = num_str.parse()?;
        let multiplier = match unit_str.to_uppercase().as_str() {
            "B" => 1.0,
            "KB" => 1024.0,
            "MB" => 1024.0 * 1024.0,
            "GB" => 1024.0 * 1024.0 * 1024.0,
            "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            "" => 1.0,
            _ => return Err(ParseSizeError::InvalidUnit(unit_str)),
        };
        Ok(Size((num * multiplier) as u64))
    }
}

impl TryFrom<&str> for Size {
    type Error = ParseSizeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Size::from_str(value)
    }
}

impl TryFrom<String> for Size {
    type Error = ParseSizeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Size::from_str(&value)
    }
}

impl<'de> Deserialize<'de> for Size {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Size::from_str(&s).map_err(serde::de::Error::custom)
    }
}
