use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base32DecodeError {
    InvalidChar { ch: u8, index: usize },
    InvalidLength { expected: usize, actual: usize },
    NonCanonicalTrailingBits,
}

impl fmt::Display for Base32DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base32DecodeError::InvalidChar { ch, index } => {
                write!(f, "invalid base32 char 0x{:02X} at index {}", ch, index)
            }
            Base32DecodeError::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {}, got {}", expected, actual)
            }
            Base32DecodeError::NonCanonicalTrailingBits => {
                write!(f, "non-canonical base32: trailing bits must be zero")
            }
        }
    }
}

impl std::error::Error for Base32DecodeError {}

pub const CROCKFORD_BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CROCKFORD_128_LEN: usize = 26;

fn decode_crockford_digit(b: u8) -> Option<u8> {
    let upper = b.to_ascii_uppercase();
    match upper {
        b'O' => return Some(0),
        b'I' | b'L' => return Some(1),
        _ => {}
    }
    CROCKFORD_BASE32_ALPHABET
        .iter()
        .position(|&ch| ch == upper)
        .map(|v| v as u8)
}

pub fn encode_crockford_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: usize = 0;

    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            let shift = bits - 5;
            let index = ((buffer >> shift) & 0x1F) as usize;
            out.push(CROCKFORD_BASE32_ALPHABET[index] as char);
            bits -= 5;
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u32 << bits) - 1;
            }
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(CROCKFORD_BASE32_ALPHABET[index] as char);
    }

    out
}

pub fn decode_crockford_base32_128(input: &str) -> Result<[u8; 16], Base32DecodeError> {
    let mut digits = Vec::with_capacity(input.len());
    for (index, b) in input.bytes().enumerate() {
        if b.is_ascii_whitespace() || b == b'-' {
            continue;
        }
        let value =
            decode_crockford_digit(b).ok_or(Base32DecodeError::InvalidChar { ch: b, index })?;
        digits.push(value);
    }

    if digits.len() != CROCKFORD_128_LEN {
        return Err(Base32DecodeError::InvalidLength {
            expected: CROCKFORD_128_LEN,
            actual: digits.len(),
        });
    }

    let mut out = Vec::with_capacity(16);
    let mut buffer: u32 = 0;
    let mut bits: usize = 0;

    for value in digits {
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            let shift = bits - 8;
            let byte = ((buffer >> shift) & 0xFF) as u8;
            out.push(byte);
            bits -= 8;
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u32 << bits) - 1;
            }
        }
    }

    if bits > 0 && buffer != 0 {
        return Err(Base32DecodeError::NonCanonicalTrailingBits);
    }

    if out.len() != 16 {
        return Err(Base32DecodeError::InvalidLength {
            expected: 16,
            actual: out.len(),
        });
    }

    let mut data = [0u8; 16];
    data.copy_from_slice(&out);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{CROCKFORD_128_LEN, decode_crockford_base32_128, encode_crockford_base32};

    #[test]
    fn crockford_base32_roundtrip() {
        let mut data = [0u8; 16];
        data[0] = 0x12;
        data[15] = 0xAB;
        let encoded = encode_crockford_base32(&data);
        let decoded = decode_crockford_base32_128(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn crockford_base32_aliases_decode() {
        let base = "0".repeat(CROCKFORD_128_LEN);
        let decoded_base = decode_crockford_base32_128(&base).unwrap();
        let mut chars: Vec<char> = base.chars().collect();
        chars[0] = 'o';
        let decoded_alias =
            decode_crockford_base32_128(&chars.into_iter().collect::<String>()).unwrap();
        assert_eq!(decoded_alias, decoded_base);

        let mut chars: Vec<char> = base.chars().collect();
        let index = CROCKFORD_128_LEN - 2;
        chars[index] = '1';
        let base_with_one: String = chars.iter().collect();
        let decoded_with_one = decode_crockford_base32_128(&base_with_one).unwrap();
        chars[index] = 'l';
        let decoded_alias_one =
            decode_crockford_base32_128(&chars.into_iter().collect::<String>()).unwrap();
        assert_eq!(decoded_alias_one, decoded_with_one);
    }
}
