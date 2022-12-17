use core::ops::Deref;
use core::ops::DerefMut;
use crc::Crc;
use crc::CRC_32_CKSUM;

use crate::icd::Request;

#[derive(Debug, PartialEq)]
pub enum Error {
    Underfill,
    Overfill,
    PostcardDecode,
    Cobs,
    Crc { expected: u32, actual: u32 },
    LogicError,
}

pub struct Accumulator<'buf> {
    buffer: &'buf mut [u8],
    idx: usize,
}

pub struct BorrowBuf<'acc, 'buf: 'acc> {
    acc: &'acc mut Accumulator<'buf>,
}

impl<'acc, 'buf: 'acc> Drop for BorrowBuf<'acc, 'buf> {
    fn drop(&mut self) {
        self.acc.idx = 0;
    }
}

impl<'acc, 'buf: 'acc> Deref for BorrowBuf<'acc, 'buf> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.acc.buffer
    }
}

impl<'acc, 'buf: 'acc> DerefMut for BorrowBuf<'acc, 'buf> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.acc.buffer
    }
}

impl<'buf> Accumulator<'buf> {
    pub fn new(buf: &'buf mut [u8]) -> Self {
        assert!(!buf.is_empty());
        Self {
            buffer: buf,
            idx: 0,
        }
    }

    pub fn push<'me>(&'me mut self, byte: u8) -> Result<Option<Request<'me>>, Error> {
        self.buffer[self.idx] = byte;
        self.idx += 1;

        if byte == 0 {
            self.finish()
        } else {
            // If we are full, and this is NOT a zero, reset the collector
            if self.idx == self.buffer.len() {
                self.idx = 0;
                Err(Error::Overfill)
            } else {
                Ok(None)
            }
        }
    }

    fn finish<'me>(&'me mut self) -> Result<Option<Request<'me>>, Error> {
        let data = self.buffer.get_mut(..self.idx).ok_or(Error::LogicError)?;
        self.idx = 0;

        let out_len = cobs::decode_in_place(data).map_err(|_| Error::Cobs)?;
        let data = data.get_mut(..out_len).ok_or(Error::LogicError)?;

        if out_len < 5 {
            // We need AT LEAST 4 bytes for CRC, and 1 byte for data.
            return Err(Error::Underfill);
        }

        let (data, crc_bytes) = data.split_at(out_len - 4);
        let mut crc_buf = [0u8; 4];
        crc_buf.copy_from_slice(crc_bytes);
        let exp_crc = u32::from_le_bytes(crc_buf);

        let crcr = Crc::<u32>::new(&CRC_32_CKSUM);
        let act_crc = crcr.checksum(data);

        if act_crc != exp_crc {
            return Err(Error::Crc {
                expected: exp_crc,
                actual: act_crc,
            });
        }

        match postcard::from_bytes::<Request<'me>>(data) {
            Ok(req) => Ok(Some(req)),
            Err(_) => Err(Error::PostcardDecode),
        }
    }

    pub fn borrow_buf<'me>(&'me mut self) -> BorrowBuf<'me, 'buf> {
        BorrowBuf { acc: self }
    }
}

#[cfg(test)]
pub mod test {
    use crc::{CRC_32_CKSUM, Crc};

    use crate::{icd::Request, machine::Accumulator};
    use cobs::encode;

    #[test]
    fn smoke() {
        let msg = Request::Ping(1234);
        let mut buf_1 = [0u8; 128];
        let mut buf_2 = [0u8; 128];
        let used = postcard::to_slice(&msg, &mut buf_1).unwrap();
        assert_eq!(used, &[0x00, 0xD2, 0x09]);

        let crcr = Crc::<u32>::new(&CRC_32_CKSUM);
        let act_crc = crcr.checksum(used);
        assert_eq!(act_crc, 0xAE5F_BE38);

        let mut ttl = Vec::new();
        ttl.extend_from_slice(used);
        ttl.extend_from_slice(&act_crc.to_le_bytes());
        let enc_used = encode(&ttl, &mut buf_2);

        let used = &buf_2[..enc_used];
        assert_eq!(used, [0x01, 0x07, 0xD2, 0x09, 0x38, 0xBE, 0x5F, 0xAE]);

        let mut buf_3 = [0u8; 128];
        let mut acc = Accumulator::new(&mut buf_3);

        for b in used {
            let res = acc.push(*b);
            assert_eq!(res, Ok(None));
        }
        let fin = acc.push(0x00);
        assert_eq!(fin, Ok(Some(msg)));
        assert_eq!(acc.idx, 0);
    }
}
