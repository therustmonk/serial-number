use std::fmt;
use std::mem;

pub type Seed = i64;

pub type Byte = u8;

pub struct Key {
    seed: Seed,
    groups: Vec<Group<Byte>>,
    checksum: Group<Byte>,
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

pub struct Group<T> {
    left: T,
    right: T,
}

impl Group<Noise> {
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

pub struct Noise {
    a: Byte,
    b: Byte,
    c: Byte,
}

impl Noise {

    pub fn new(a: Byte, b: Byte, c: Byte) -> Self {
        Noise {
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

pub struct Generator {
    noise: Vec<Group<Noise>>,
}

impl Generator {
    pub fn make_key(&self, seed: Seed) -> Key {
        let groups: Vec<Group<Byte>> = self.noise.iter().map(|g| g.produce(seed)).collect();
        let checksum = checksum(seed, &groups);
        Key {
            seed: seed,
            groups: groups,
            checksum: checksum,
        }
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

    #[test]
    fn it_works() {
        let group = Group {
            left: Noise::new(1,2,3),
            right: Noise::new(5, 6, 7),
        };
        let generator = Generator {
            noise: vec![(group)],
        };
        println!("SERIAL KEY IS: {}", generator.make_key(213));
    }
}
