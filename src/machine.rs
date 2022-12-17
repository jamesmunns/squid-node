use core::ops::Deref;
use core::ops::DerefMut;
use crc::Crc;
use crc::Digest;
use crc::CRC_32_CKSUM;

use crate::icd::DataChunk;
use crate::icd::Request;
use crate::icd::Response;
use crate::icd::ResponseError;
use crate::icd::StartBootload;
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
            let buffer = core::mem::take(&mut self.acc.buffer);
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

    pub fn push(&mut self, byte: u8) -> Result<Option<Request<'_>>, Error> {
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

    fn finish(&mut self) -> Result<Option<Request<'_>>, Error> {
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

        match postcard::from_bytes::<Request<'_>>(data) {
            Ok(req) => Ok(Some(req)),
            Err(_) => Err(Error::PostcardDecode),
        }
    }

    pub fn borrow_buf<'me>(&'me mut self) -> BorrowBuf<'me, 'buf> {
        BorrowBuf { acc: self }
    }
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_CKSUM);

struct BootLoadMeta {
    digest_running: Digest<'static, u32>,
    addr_start: u32,
    addr_current: u32,
    length: u32,
    exp_crc: u32,
}

enum Mode {
    Idle,
    BootLoad(BootLoadMeta),
    RebootPending,
}

pub struct State {
    pending_resp: Option<Result<Response<'static>, ResponseError>>,
    mode: Mode,
}

pub struct Machine<'buf> {
    acc: Accumulator<'buf>,
    state: State,
}

impl<'buf> Machine<'buf> {
    pub fn push<'me>(&'me mut self, byte: u8) -> Option<BorrowBuf<'me, 'buf>> {
        let Machine { acc, state } = self;

        match acc.push(byte) {
            Ok(None) => None,
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
            Request::StartBootload(sb) => {
                let response;
                self.mode = match core::mem::replace(&mut self.mode, Mode::Idle) {
                    Mode::Idle => {
                        let (resp, mode) = self.handle_start(sb);
                        response = resp;
                        mode
                    }
                    Mode::BootLoad(_) => todo!(),
                    Mode::RebootPending => {
                        response = Err(ResponseError::BootloadInProgress);
                        Mode::RebootPending
                    }
                };
                response
            }
            Request::DataChunk(dc) => {
                let response;
                self.mode = match core::mem::replace(&mut self.mode, Mode::Idle) {
                    Mode::Idle => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::Idle
                    }
                    Mode::BootLoad(meta) => {
                        let (resp, mode) = self.handle_chunk(meta, dc);
                        response = resp;
                        mode
                    }
                    Mode::RebootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::RebootPending
                    }
                };
                response
            }
            Request::CompleteBootload { reboot } => {
                let response;
                self.mode = match core::mem::replace(&mut self.mode, Mode::Idle) {
                    Mode::Idle => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::Idle
                    }
                    Mode::BootLoad(meta) => {
                        let (resp, mode) = self.handle_complete(meta, reboot);
                        response = resp;
                        mode
                    }
                    Mode::RebootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::RebootPending
                    }
                };
                response
            }
            Request::GetSettings => Ok(Response::Settings {
                data: &[],
                crc32: 0x0000_0000,
            }),
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
            }
            Request::GetStatus => Ok(Response::Status({
                match &self.mode {
                    Mode::Idle => Status::Idle,
                    Mode::BootLoad(meta) => {
                        if meta.addr_start == meta.addr_current {
                            Status::Started {
                                start_addr: meta.addr_start,
                                length: meta.length,
                                crc32: meta.exp_crc,
                            }
                        } else if meta.addr_current == (meta.addr_start + meta.length) {
                            Status::AwaitingComplete
                        } else {
                            Status::Loading {
                                start_addr: meta.addr_start,
                                next_addr: meta.addr_current,
                                partial_crc32: meta.digest_running.clone().finalize(),
                                expected_crc32: meta.exp_crc,
                            }
                        }
                    }
                    Mode::RebootPending => Status::Idle,
                }
            })),
            Request::ReadRange { .. } => todo!(),
            Request::AbortBootload => {
                let mode = core::mem::replace(&mut self.mode, Mode::Idle);
                let response;
                self.mode = match mode {
                    Mode::Idle => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::Idle
                    }
                    Mode::BootLoad(_meta) => {
                        response = Ok(Response::BootloadAborted);
                        Mode::Idle
                    }
                    Mode::RebootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::RebootPending
                    }
                };
                response
            }
        }
    }

    fn handle_complete(
        &mut self,
        meta: BootLoadMeta,
        reboot: bool,
    ) -> (Result<Response<'static>, ResponseError>, Mode) {
        let complete = meta.addr_current == (meta.addr_start + meta.length);
        let response;
        let mode = if !complete {
            response = Err(ResponseError::IncompleteLoad {
                expected_len: meta.length,
                actual_len: meta.addr_current - meta.addr_start,
            });
            Mode::BootLoad(meta)
        } else {
            let calc_crc = meta.digest_running.finalize();
            if calc_crc != meta.exp_crc {
                response = Err(ResponseError::BadFullCrc {
                    expected: meta.exp_crc,
                    actual: calc_crc,
                });
                Mode::Idle
            } else {
                response = Ok(Response::ConfirmComplete {
                    will_reboot: reboot,
                });
                if reboot {
                    Mode::RebootPending
                } else {
                    Mode::Idle
                }
            }
        };
        (response, mode)
    }

    fn handle_chunk(
        &mut self,
        mut meta: BootLoadMeta,
        dc: DataChunk<'_>,
    ) -> (Result<Response<'static>, ResponseError>, Mode) {
        if dc.data_addr != meta.addr_current {
            return (
                Err(ResponseError::SkippedRange {
                    expected: meta.addr_current,
                    actual: dc.data_addr,
                }),
                Mode::BootLoad(meta),
            );
        }
        if dc.data.len() != (2 * 1024) {
            return (
                Err(ResponseError::IncorrectLength {
                    expected: 2 * 1024,
                    actual: dc.data.len() as u32,
                }),
                Mode::BootLoad(meta),
            );
        }
        if meta.addr_current >= (meta.addr_start + meta.length) {
            return (Err(ResponseError::TooManyChunks), Mode::BootLoad(meta));
        }

        let crcr = Crc::<u32>::new(&CRC_32_CKSUM);
        let calc_crc = crcr.checksum(dc.data);
        if calc_crc != dc.sub_crc32 {
            return (
                Err(ResponseError::BadSubCrc {
                    expected: dc.sub_crc32,
                    actual: calc_crc,
                }),
                Mode::BootLoad(meta),
            );
        }

        self.flash_range(dc.data_addr, dc.data);
        meta.digest_running.update(dc.data);
        meta.addr_current += 2 * 1024;

        (
            Ok(Response::ChunkAccepted {
                data_addr: dc.data_addr,
                data_len: dc.data.len() as u32,
                crc32: calc_crc,
            }),
            Mode::BootLoad(meta),
        )
    }

    fn handle_start(
        &mut self,
        sb: StartBootload,
    ) -> (Result<Response<'static>, ResponseError>, Mode) {
        if sb.start_addr != (0x0000_0000 + 16 * 1024) {
            return (Err(ResponseError::BadStartAddress), Mode::Idle);
        }
        let too_long = sb.length >= ((64 - 16) * 1024);
        let not_full = (sb.length & (1024 - 1)) != 0;
        if too_long || not_full {
            return (Err(ResponseError::BadLength), Mode::Idle);
        }

        self.erase_range(sb.start_addr, sb.length);

        (
            Ok(Response::BootloadStarted),
            Mode::BootLoad(BootLoadMeta {
                digest_running: CRC.digest(),
                addr_start: sb.start_addr,
                addr_current: sb.start_addr,
                length: sb.length,
                exp_crc: sb.crc32,
            }),
        )
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
