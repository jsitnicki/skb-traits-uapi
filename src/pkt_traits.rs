/// Packet traits K/V storage
use std::fmt;
use std::mem;

use self::Error::*;

#[repr(C)]
struct PktTraitsHdr {
    high: u64,
    low: u64,
}

impl PktTraitsHdr {
    const HEADER_SIZE: usize = mem::size_of::<PktTraitsHdr>();

    fn values_size(&self) -> usize {
        ((self.high.count_ones() << 2)
            + (self.low.count_ones() << 1)
            + ((self.high & self.low).count_ones() << 1)) as _
    }

    fn traits_size(&self) -> usize {
        Self::HEADER_SIZE + self.values_size()
    }

    fn is_key_set(&self, key: TraitKey) -> bool {
        (self.high | self.low) & (1 << key) != 0
    }

    fn mask(&self, mask: u64) -> PktTraitsHdr {
        PktTraitsHdr {
            high: self.high & mask,
            low: self.low & mask,
        }
    }

    fn value_offset(&self, key: u8) -> usize {
        let m = !(!0u64 << key);
        self.mask(m).traits_size()
    }

    fn value_len(&self, key: u8) -> usize {
        let m = 1u64 << key;
        self.mask(m).values_size()
    }
}

impl From<[u8; 16]> for PktTraitsHdr {
    fn from(bytes: [u8; 16]) -> Self {
        let high = bytes[0..8].try_into().unwrap();
        let low = bytes[8..16].try_into().unwrap();

        PktTraitsHdr {
            high: u64::from_ne_bytes(high),
            low: u64::from_ne_bytes(low),
        }
    }
}

impl TryFrom<&[u8]> for PktTraitsHdr {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<PktTraitsHdr, Self::Error> {
        let h: [u8; 16] = bytes[0..16].try_into().unwrap();
        Ok(h.into())
    }
}


pub struct PktTraits {
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    #[allow(dead_code)]
    InvalidSize(String),
    #[allow(dead_code)]
    KeyRange(String),
}

impl std::error::Error for Error {}

// Errors should be printable.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            InvalidSize(msg) => write!(f, "{}", msg),
            KeyRange(msg) => write!(f, "{}", msg),
        }
    }
}

impl TryFrom<Vec<u8>> for PktTraits {
    type Error = Error;

    fn try_from(blob: Vec<u8>) -> Result<PktTraits, Self::Error> {
        if blob.len() < PktTraitsHdr::HEADER_SIZE {
            return Err(InvalidSize(format!(
                "Expected at least {} bytes, got only {}",
                PktTraitsHdr::HEADER_SIZE,
                blob.len(),
            )));
        }

        let h = PktTraitsHdr::try_from(&blob[..]).unwrap();

        if blob.len() != h.traits_size() {
            return Err(InvalidSize(format!(
                "Expected exactly {} bytes, got {}",
                h.traits_size(),
                blob.len()
            )));
        }

        Ok(PktTraits {
            data: Vec::from(blob),
        })
    }
}

type TraitKey = u8;

#[derive(Debug, PartialEq)]
pub enum TraitValue {
    U16(u16),
    U32(u32),
    U64(u64),
}

impl PktTraits {
    const MAX_KEY: TraitKey = (u64::BITS - 1) as u8;

    pub fn get(&self, key: TraitKey) -> Result<Option<TraitValue>, Error> {
        if key > Self::MAX_KEY {
            return Err(KeyRange(format!(
                "Key must be in 0..{} range, got {}",
                Self::MAX_KEY,
                key
            )));
        }

        let h = self.header();

        if !h.is_key_set(key) {
            return Ok(None);
        }

        let off = h.value_offset(key);
        let len = h.value_len(key);
        let val = &self.data[off..off + len];
        let val = match val.len() {
            2 => TraitValue::U16(u16::from_ne_bytes(val.try_into().unwrap())),
            4 => TraitValue::U32(u32::from_ne_bytes(val.try_into().unwrap())),
            8 => TraitValue::U64(u64::from_ne_bytes(val.try_into().unwrap())),
            _ => unreachable!(),
        };

        Ok(Some(val))
    }

    fn header(&self) -> PktTraitsHdr {
        let bytes: [u8; 16] = self.data[0..PktTraitsHdr::HEADER_SIZE].try_into().unwrap();
        PktTraitsHdr::from(bytes)
    }
}
