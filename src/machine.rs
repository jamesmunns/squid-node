use core::ops::Deref;
use core::ops::DerefMut;
use crc::Crc;
use crc::CRC_32_CKSUM;
use crc::Digest;

use crate::icd::Request;
use crate::icd::Response;
use crate::icd::ResponseError;
use crate::icd::Status;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

impl<'acc, 'buf: 'acc> BorrowBuf<'acc, 'buf> {
    pub fn shrink_to(&mut self, size: usize) {
        if size < self.acc.buffer.len() {
            // NOTE: Morally equivalent to:
            // self.acc.buffer = &mut self.acc.buffer[..size];
            let buffer = core::mem::replace(&mut self.acc.buffer, &mut []);
            let (start, _end) = buffer.split_at_mut(size);
            self.acc.buffer = start;
        }
    }
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

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);

pub struct State {
    pending_resp: Option<Result<Response<'static>, ResponseError>>,
    bootload_active: bool,
    reboot_pending: bool,
    bl_digest_running: Option<Digest<'static, u32>>,
    bl_addr_start: u32,
    bl_addr_current: u32,
    bl_length: u32,
    bl_exp_crc: u32,
}

pub struct Machine<'buf> {
    acc: Accumulator<'buf>,
    state: State,
}

impl<'buf> Machine<'buf> {
    pub fn push<'me>(&'me mut self, byte: u8) -> Option<BorrowBuf<'me, 'buf>> {
        let Machine { acc, state } = self;

        match acc.push(byte) {
            Ok(None) => return None,
            Ok(Some(msg)) => {
                state.handle_msg(msg);
                Some(state.respond(acc.borrow_buf()))
            }
            Err(_e) => {
                // TODO: Encode this:
                // return Some(Err(ResponseError::LineNak(e)))
                None
            }
        }
    }
}

impl State {
    pub fn handle_msg(&mut self, msg: Request<'_>) {
        self.pending_resp = Some(self.handle_msg_inner(msg));
    }

    #[inline]
    fn handle_msg_inner(&mut self, msg: Request<'_>) -> Result<Response<'static>, ResponseError> {
        match msg {
            Request::Ping(n) => Ok(Response::Pong(n)),
            Request::GetParameters => Ok(Response::Parameters {
                settings_max: 2 * 1024,
                data_chunk_size: 2 * 1024,
                valid_ram_read: (0x2000_0000, 0x2000_0000 + (8 * 1024)),
                valid_flash_read: (0x0000_0000, 0x0000_0000 + (64 * 1024)),
                read_max: 2 * 1024,
            }),
            Request::StartBootload {
                start_addr,
                length,
                crc32,
            } => {
                if self.bootload_active {
                    return Err(ResponseError::BootloadInProgress);
                }
                if start_addr != (0x0000_0000 + 16 * 1024) {
                    return Err(ResponseError::BadStartAddress);
                }
                let too_long = length >= ((64 - 16) * 1024);
                let not_full = (length & (1024 - 1)) != 0;
                if too_long || not_full {
                    return Err(ResponseError::BadLength);
                }

                self.bootload_active = true;
                self.bl_digest_running = Some(CRC.digest());
                self.bl_addr_start = start_addr;
                self.bl_addr_current = start_addr;
                self.bl_length = length;
                self.bl_exp_crc = crc32;

                self.erase_range(start_addr, length);

                Ok(Response::BootloadStarted)
            }
            Request::DataChunk {
                data_addr,
                sub_crc32,
                data,
            } => {
                if !self.bootload_active {
                    return Err(ResponseError::NoBootloadActive);
                }
                if data_addr != self.bl_addr_current {
                    return Err(ResponseError::SkippedRange {
                        expected: self.bl_addr_current,
                        actual: data_addr,
                    });
                }
                if data.len() != (2 * 1024) {
                    return Err(ResponseError::IncorrectLength {
                        expected: 2 * 1024,
                        actual: data.len() as u32,
                    });
                }
                if self.bl_addr_current >= (self.bl_addr_start + self.bl_length) {
                    return Err(ResponseError::TooManyChunks);
                }

                let crcr = Crc::<u32>::new(&CRC_32_CKSUM);
                let calc_crc = crcr.checksum(data);
                if calc_crc != sub_crc32 {
                    return Err(ResponseError::BadSubCrc {
                        expected: sub_crc32,
                        actual: calc_crc,
                    });
                }

                self.flash_range(data_addr, data);
                match self.bl_digest_running.as_mut() {
                    Some(bldr) => bldr.update(data),
                    None => return Err(ResponseError::Oops),
                }
                self.bl_addr_current += 2 * 1024;

                Ok(Response::ChunkAccepted {
                    data_addr,
                    data_len: data.len() as u32,
                    crc32: calc_crc,
                })
            }
            Request::CompleteBootload { reboot } => {
                if !self.bootload_active {
                    return Err(ResponseError::NoBootloadActive);
                }
                let complete = self.bl_addr_current == (self.bl_addr_start + self.bl_length);
                if !complete {
                    return Err(ResponseError::IncompleteLoad {
                        expected_len: self.bl_length,
                        actual_len: self.bl_addr_current - self.bl_addr_start,
                    });
                }
                let calc_crc = match self.bl_digest_running.take() {
                    Some(bldr) => bldr.finalize(),
                    None => return Err(ResponseError::Oops),
                };
                if calc_crc != self.bl_exp_crc {
                    return Err(ResponseError::BadFullCrc {
                        expected: self.bl_exp_crc,
                        actual: calc_crc,
                    });
                }
                self.reboot_pending = reboot;
                Ok(Response::ConfirmComplete { will_reboot: reboot })
            },
            Request::GetSettings => Ok(Response::Settings { data: &[], crc32: 0x0000_0000 }),
            Request::WriteSettings { crc32, data } => {
                if data.len() > (2 * 1024) {
                    return Err(ResponseError::SettingsTooLong {
                        max: 2 * 1024,
                        actual: data.len() as u32,
                    });
                }
                let act_crc = CRC.checksum(data);
                if act_crc != crc32 {
                    return Err(ResponseError::BadSettingsCrc {
                        expected: crc32,
                        actual: act_crc,
                    });
                }
                self.write_settings(data);
                Ok(Response::SettingsAccepted {
                    data_len: data.len() as u32,
                    crc32: act_crc,
                })
            },
            Request::GetStatus => {
                Ok(Response::Status({
                    if !self.bootload_active {
                        Status::Idle
                    } else if self.bl_addr_start == self.bl_addr_current {
                        Status::Started {
                            start_addr: self.bl_addr_start,
                            length: self.bl_length,
                            crc32: self.bl_exp_crc,
                        }
                    } else if self.bl_addr_current == (self.bl_addr_start + self.bl_length) {
                        Status::AwaitingComplete
                    } else {
                        if let Some(digest) = self.bl_digest_running.as_ref() {
                            Status::Loading {
                                start_addr: self.bl_addr_start,
                                next_addr: self.bl_addr_current,
                                partial_crc32: digest.clone().finalize(),
                                expected_crc32: self.bl_exp_crc,
                            }
                        } else {
                            return Err(ResponseError::Oops);
                        }
                    }
                }))
            },
            Request::ReadRange { .. } => todo!(),
            Request::AbortBootload => {
                if self.bootload_active {
                    self.bootload_active = false;
                    self.reboot_pending = false;
                    self.bl_digest_running = None;
                    self.bl_addr_start = 0;
                    self.bl_addr_current = 0;
                    self.bl_length = 0;
                    self.bl_exp_crc = 0;
                    Ok(Response::BootloadAborted)
                } else {
                    Err(ResponseError::NoBootloadActive)
                }
            },
        }
    }

    pub fn respond<'a, 'b>(&mut self, mut buf: BorrowBuf<'a, 'b>) -> BorrowBuf<'a, 'b> {
        let msg = self.pending_resp.take().unwrap_or(Err(ResponseError::Oops));
        let _msg = match msg {
            Ok(ok_msg) => Ok(match ok_msg {
                // These require "re-work"!
                Response::ReadRange { .. } => todo!(),
                Response::Settings { .. } => todo!(),
                other => other,
            }),
            Err(err_msg) => Err(err_msg),
        };

        // TODO! Encode and stuff
        buf.shrink_to(0);
        buf
    }

    fn flash_range(&mut self, _start: u32, _data: &[u8]) {
        todo!()
    }

    fn erase_range(&mut self, _start: u32, _len: u32) {
        todo!()
    }

    fn write_settings(&mut self, _data: &[u8]) {
        todo!()
    }
}

#[cfg(test)]
pub mod feat_test {
    #[test]
    fn features() {
        if !cfg!(feature = "use-std") {
            println!();
            println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            println!("run tests with 'use-std' feature enabled!");
            println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            println!();
            panic!();
        }
    }
}

#[cfg(all(test, feature = "use-std"))]
pub mod test {
    use crate::{icd::Request, machine::Accumulator};

    #[test]
    fn accumulator_smoke() {
        let msg = Request::Ping(1234);
        let mut enc_used = msg.encode_to_vec();
        assert_eq!(
            &enc_used,
            &[0x01, 0x07, 0xD2, 0x09, 0x38, 0xBE, 0x5F, 0xAE, 0x00]
        );
        // Pop off the terminator, we'll do that manually
        enc_used.pop();

        let mut acc_buf = [0u8; 128];
        let mut acc = Accumulator::new(&mut acc_buf);

        for b in enc_used.iter() {
            let res = acc.push(*b);
            assert_eq!(res, Ok(None));
        }
        let fin = acc.push(0x00);
        assert_eq!(fin, Ok(Some(msg)));
        assert_eq!(acc.idx, 0);
    }
}
