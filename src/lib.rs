use std::fmt;
use std::mem;
use std::str;
use std::u8;
use std::i64;
use std::num;

pub type Seed = i64;

pub type Byte = u8;

#[derive(Debug)]
pub enum Error {
    NotEnoughItems,
    InvalidFragment,
    InvalidFormat,
}

impl From<num::ParseIntError> for Error {
    fn from(_: num::ParseIntError) -> Self {
        Error::InvalidFormat
    }
}

#[derive(PartialEq, Debug)]
pub struct Key {
    seed: Seed,
    groups: Vec<Group<Byte>>,
    checksum: Group<Byte>,
}

impl Key {
    pub fn new(seed: Seed, secret: &[Group<Block>]) -> Self {
        let groups: Vec<Group<Byte>> = secret.iter().map(|g| g.produce(seed)).collect();
        let checksum = checksum(seed, &groups);
        Key {
            seed: seed,
            groups: groups,
            checksum: checksum,
        }
    }

    pub fn valid(&self, secret: &[Group<Block>]) -> bool {
        let valid_key = Key::new(self.seed, secret);
        self == &valid_key
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{:04X}", self.seed));
        for group in &self.groups {
            try!(write!(f, "-{}", group));
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
            let seed = try!(i64::from_str_radix(&seed, 16));
            let mut groups = Vec::new();
            for fragment in tail {
                if fragment.len() != 4 {
                    return Err(Error::InvalidFragment);
                }
                let left = try!(u8::from_str_radix(&fragment[0..2], 16));
                let right = try!(u8::from_str_radix(&fragment[2..4], 16));
                let group = Group {
                    left: left,
                    right: right,
                };
                groups.push(group);
            }
            let checksum = groups.pop().unwrap();
            let key = Key {
                seed: seed,
                groups: groups,
                checksum: checksum,
            };
            Ok(key)
        } else {
            Err(Error::NotEnoughItems)
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Group<T> {
    left: T,
    right: T,
}

impl Group<Block> {
    fn produce(&self, seed: Seed) -> Group<Byte> {
        Group {
            left: self.left.produce(seed),
            right: self.right.produce(seed),
        }
    }
}

impl fmt::Display for Group<Byte> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02X}{:02X}", self.left, self.right)
    }
}

pub struct Block {
    a: Byte,
    b: Byte,
    c: Byte,
}

impl Block {

    pub fn new(a: Byte, b: Byte, c: Byte) -> Self {
        Block {
            a: a,
            b: b,
            c: c,
        }
    }

    fn produce(&self, seed: Seed) -> Byte {
        let a = (seed >> (self.a % 25)) as Byte;
        let b = (seed >> (self.b % 3)) as Byte;
        let c = if self.a % 2 == 0 { b | self.c } else { b & self.c };
        a ^ c
    }
}

fn checksum(seed: Seed, groups: &[Group<Byte>]) -> Group<Byte> {
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
        let bytes: [u8; 8] = unsafe { mem::transmute(seed.to_be()) };
        update(&bytes);
        for item in groups {
            update(&[item.left, item.right]);
        }
    }
    Group {
        left: left as Byte,
        right: right as Byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_generate() {
        let group = Group {
            left: Block::new(1, 2, 3),
            right: Block::new(5, 6, 7),
        };
        let secret = vec![(group)];
        let key = Key::new(123, &secret);
        let right_key = Key::from_str("007B-3F00-246A").unwrap();
        let wrong_key = Key::from_str("007B-3F00-246B").unwrap();
        assert_eq!(key, right_key);
        assert!(!wrong_key.valid(&secret));
    }

    #[test]
    fn test_restore() {
        let key = Key::from_str("1233-A5B6-4324").unwrap();
        assert_eq!(&format!("{}", key), "1233-A5B6-4324");
    }

}
