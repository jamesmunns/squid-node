#![cfg_attr(not(any(test, feature = "use-std")), no_std)]

use crc::{CRC_32_CKSUM, Crc};

pub mod icd;
pub mod machine;

pub const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);
