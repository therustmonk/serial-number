//! Rust library to generate and check software serial-numbers.
//!
//! [Source 1](http://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi/)
//! [Source 2](https://github.com/garethrbrown/.net-licence-key-generator/blob/master/AppSoftware.LicenceEngine.KeyGenerator/PkvLicenceKeyGenerator.cs)

use std::fmt;
use std::i64;
use std::str;
use std::u8;
use thiserror::Error;

pub type Seed = i64;

pub type Byte = u8;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not enough items")]
    NotEnoughItems,
    #[error("invalid fragment")]
    InvalidFragment,
    #[error("invalid format: {0}")]
    InvalidFormat(#[from] std::num::ParseIntError),
    #[error("invalid int: {0}")]
    InvalidInt(#[from] std::num::TryFromIntError),
}

#[derive(Clone)]
pub struct Secret {
    /// Groups of blocks
    pairs: Vec<Pair<Block>>,
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.pairs.iter();
        let mut first = true;
        while let Some(pair) = iter.next() {
            if !first {
                write!(f, "-")?;
            }
            first = false;
            write!(f, "{}", pair)?;
        }
        Ok(())
    }
}

impl str::FromStr for Secret {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fragments: Vec<&str> = s.split("-").collect();
        let mut pairs = Vec::new();
        for fragment in fragments {
            if fragment.len() != 12 {
                return Err(Error::InvalidFragment);
            }
            let left_a = u8::from_str_radix(&fragment[0..2], 16)?;
            let left_b = u8::from_str_radix(&fragment[2..4], 16)?;
            let left_c = u8::from_str_radix(&fragment[4..6], 16)?;
            let right_a = u8::from_str_radix(&fragment[6..8], 16)?;
            let right_b = u8::from_str_radix(&fragment[8..10], 16)?;
            let right_c = u8::from_str_radix(&fragment[10..12], 16)?;
            let pair = Pair {
                left: Block::new(left_a, left_b, left_c),
                right: Block::new(right_a, right_b, right_c),
            };
            pairs.push(pair);
        }
        Ok(Secret { pairs })
    }
}

#[derive(PartialEq, Debug)]
pub struct Key {
    seed: Seed,
    pairs: Vec<Pair<Byte>>,
    checksum: Pair<Byte>,
}

impl Key {
    pub fn create(seed: Seed, secret: &Secret) -> Result<Self, Error> {
        let pairs: Vec<Pair<Byte>> = secret
            .pairs
            .iter()
            .map(|g| g.produce(seed))
            .collect::<Result<_, _>>()?;
        let checksum = checksum(seed, &pairs)?;
        Ok(Key {
            seed: seed,
            pairs: pairs,
            checksum: checksum,
        })
    }

    pub fn valid(&self, secret: &Secret) -> bool {
        Key::create(self.seed, secret)
            .map(|valid_key| self == &valid_key)
            .unwrap_or_default()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04X}", self.seed)?;
        for pair in &self.pairs {
            write!(f, "-{}", pair)?;
        }
        write!(f, "-{}", self.checksum)
    }
}

impl str::FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items: Vec<&str> = s.split("-").collect();
        if items.len() < 3 {
            return Err(Error::NotEnoughItems);
        }
        if let Some((seed, tail)) = items.split_first() {
            let seed = i64::from_str_radix(&seed, 16)?;
            let mut pairs = Vec::new();
            for fragment in tail {
                if fragment.len() != 4 {
                    return Err(Error::InvalidFragment);
                }
                let left = u8::from_str_radix(&fragment[0..2], 16)?;
                let right = u8::from_str_radix(&fragment[2..4], 16)?;
                let pair = Pair {
                    left: left,
                    right: right,
                };
                pairs.push(pair);
            }
            let checksum = pairs.pop().unwrap();
            let key = Key {
                seed: seed,
                pairs: pairs,
                checksum: checksum,
            };
            Ok(key)
        } else {
            Err(Error::NotEnoughItems)
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Pair<T> {
    left: T,
    right: T,
}

impl Pair<Block> {
    fn produce(&self, seed: Seed) -> Result<Pair<Byte>, Error> {
        Ok(Pair {
            left: self.left.produce(seed)?,
            right: self.right.produce(seed)?,
        })
    }
}

impl fmt::Display for Pair<Byte> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02X}{:02X}", self.left, self.right)
    }
}

impl fmt::Display for Pair<Block> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.left, self.right)
    }
}

#[derive(Clone)]
pub struct Block {
    a: Byte,
    b: Byte,
    c: Byte,
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02X}{:02X}{:02X}", self.a, self.b, self.c)
    }
}

impl Block {
    pub fn new(a: Byte, b: Byte, c: Byte) -> Self {
        Block { a: a, b: b, c: c }
    }

    fn produce(&self, seed: Seed) -> Result<Byte, Error> {
        let a: u8 = (seed >> (self.a % 25)).try_into()?;
        let b: u8 = (seed >> (self.b % 3)).try_into()?;
        let c = if self.a % 2 == 0 {
            b | self.c
        } else {
            b & self.c
        };
        Ok(a ^ c)
    }
}

fn checksum(seed: Seed, pairs: &[Pair<Byte>]) -> Result<Pair<Byte>, Error> {
    let mut left: u16 = 0x56;
    let mut right: u16 = 0xAF;
    {
        let mut update = |slice: &[u8]| {
            for byte in slice {
                right = right + *byte as u16;

                if right > 0xFF {
                    right -= 0xFF;
                }

                left += right;

                if left > 0xFF {
                    left -= 0xFF;
                }
            }
        };
        let bytes: [u8; 8] = seed.to_be_bytes();
        update(&bytes);
        for item in pairs {
            update(&[item.left, item.right]);
        }
    }
    Ok(Pair {
        left: left.try_into()?,
        right: right.try_into()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_validation() {
        let secret = Secret::from_str("0A6BBFAA6793-ABB734930FCD").unwrap();
        let key = Key::create(123, &secret).unwrap();
        let right_key = Key::from_str("007B-BFBF-3049-E324").unwrap();
        let wrong_key = Key::from_str("0070-BFBF-3049-E324").unwrap();
        assert_eq!(key, right_key);
        assert!(!wrong_key.valid(&secret));
    }

    #[test]
    fn test_format() {
        const SECRET: &str = "0A6BBFAA6793-ABB734930FCD";
        let secret = Secret::from_str(SECRET).unwrap();
        assert_eq!(&format!("{}", secret), SECRET);

        const KEY: &str = "1233-A5B6-4324";
        let key = Key::from_str(KEY).unwrap();
        assert_eq!(&format!("{}", key), KEY);
    }
}
