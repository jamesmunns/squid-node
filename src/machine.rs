use core::ops::Deref;
use core::ops::DerefMut;
use crc::Crc;
use crc::Digest;
use crc::CRC_32_CKSUM;

use crate::icd::DataChunk;
use crate::icd::Parameters;
use crate::icd::Request;
use crate::icd::Response;
use crate::icd::ResponseError;
use crate::icd::StartBootload;
use crate::icd::Status;
use crate::CRC;
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
        Ok(Some(crate::icd::decode_in_place(data)?))
    }

    pub fn borrow_buf<'me>(&'me mut self) -> BorrowBuf<'me, 'buf> {
        BorrowBuf { acc: self }
    }
}

pub trait Flash {
    fn flash_range(&mut self, _start: u32, _data: &[u8]);
    fn erase_range(&mut self, _start: u32, _len: u32);
    fn write_settings(&mut self, _data: &[u8], crc: u32);
    fn read_range(&mut self, start_addr: u32, len: u32) -> &[u8];
    fn parameters(&self) -> &Parameters;
}

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

fn stm32g031_params() -> Parameters {
    Parameters {
        settings_max: (2 * 1024) - 4,
        data_chunk_size: 2 * 1024,
        valid_flash_range: (0x0000_0000, 0x0000_0000 + (64 * 1024)),
        valid_app_range: (0x0000_0000 + (16 * 1024), 0x0000_0000 + (64 * 1024)),
        read_max: 2 * 1024,
    }
}

pub struct State<HW: Flash> {
    pending_resp: Option<Result<Response<'static>, ResponseError>>,
    mode: Mode,
    hardware: HW,
}

pub struct Machine<'buf, HW: Flash> {
    acc: Accumulator<'buf>,
    state: State<HW>,
}

impl<'buf, HW: Flash> Machine<'buf, HW> {
    pub fn new(buf: &'buf mut [u8], hw: HW) -> Self {
        let acc = Accumulator::new(buf);
        let state = State {
            pending_resp: None,
            mode: Mode::Idle,
            hardware: hw,
        };
        Self { acc, state }
    }

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

impl<HW: Flash> State<HW> {
    pub fn handle_msg(&mut self, msg: Request<'_>) {
        self.pending_resp = Some(self.handle_msg_inner(msg));
    }

    #[inline]
    fn handle_msg_inner(&mut self, msg: Request<'_>) -> Result<Response<'static>, ResponseError> {
        match msg {
            Request::Ping(n) => Ok(Response::Pong(n)),
            Request::GetParameters => Ok(Response::Parameters(*self.hardware.parameters())),
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
                if data.len() as u32 > self.hardware.parameters().settings_max {
                    return Err(ResponseError::SettingsTooLong {
                        max: self.hardware.parameters().settings_max,
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
                self.hardware.write_settings(data, act_crc);
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
            Request::ReadRange { start_addr, len } => {
                let start_ok = start_addr >= self.hardware.parameters().valid_flash_range.0;
                if !start_ok {
                    return Err(ResponseError::BadRangeStart);
                }

                if let Some(end) = start_addr.checked_add(len) {
                    if end <= self.hardware.parameters().valid_flash_range.1 {
                        Ok(Response::ReadRange {
                            start_addr,
                            len,
                            data: &[],
                        })
                    } else {
                        Err(ResponseError::BadRangeEnd)
                    }
                } else {
                    Err(ResponseError::BadRangeEnd)
                }
            }
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
        if dc.data.len() as u32 != self.hardware.parameters().data_chunk_size {
            return (
                Err(ResponseError::IncorrectLength {
                    expected: self.hardware.parameters().data_chunk_size,
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

        self.hardware.flash_range(dc.data_addr, dc.data);
        meta.digest_running.update(dc.data);
        meta.addr_current += self.hardware.parameters().data_chunk_size;

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
        if sb.start_addr != self.hardware.parameters().valid_app_range.0 {
            return (Err(ResponseError::BadStartAddress), Mode::Idle);
        }
        let too_long = sb.length
            >= (self.hardware.parameters().valid_app_range.1
                - self.hardware.parameters().valid_app_range.0);
        let not_full = (sb.length & (self.hardware.parameters().data_chunk_size - 1)) != 0;
        if too_long || not_full {
            return (Err(ResponseError::BadLength), Mode::Idle);
        }

        self.hardware.erase_range(sb.start_addr, sb.length);

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
        let msg = match msg {
            Ok(ok_msg) => Ok(match ok_msg {
                // These require "re-work"!
                Response::ReadRange {
                    start_addr,
                    len,
                    data: _,
                } => {
                    let read = self.hardware.read_range(start_addr, len);
                    Response::ReadRange {
                        start_addr,
                        len,
                        data: read,
                    }
                }
                Response::Settings { .. } => todo!(),
                other => other,
            }),
            Err(err_msg) => Err(err_msg),
        };

        let dbuf: &mut [u8] = &mut buf;
        match crate::icd::encode_resp_to_slice(&msg, dbuf) {
            Ok(used) => {
                let len = used.len();
                buf.shrink_to(len);
            }
            Err(_) => {
                // welp.
                // TODO! Encode and stuff
                buf.shrink_to(0);
            }
        };
        buf
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
    use core::sync::atomic::{AtomicU32, Ordering};

    use crate::{
        icd::{Parameters, Request, Response, ResponseError},
        machine::{stm32g031_params, Accumulator, Machine},
    };

    use super::Flash;

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

    #[test]
    fn machine_smoke() {
        let msg = Request::Ping(1234);
        let mut enc_used = msg.encode_to_vec();
        assert_eq!(
            &enc_used,
            &[0x01, 0x07, 0xD2, 0x09, 0x38, 0xBE, 0x5F, 0xAE, 0x00]
        );
        // Pop off the terminator, we'll do that manually
        enc_used.pop();

        let mut acc_buf = [0u8; 128];
        let hw_inner = HwInner::default();
        let hw = AtomicHardware {
            inner: &hw_inner,
            parameters: stm32g031_params(),
        };

        let mut machine = Machine::new(&mut acc_buf, hw);

        for b in enc_used.iter() {
            let res = machine.push(*b);
            assert!(matches!(res, None));
        }
        let fin = machine.push(0x00);
        let fin_buf = fin.unwrap();
        let mut fin_vec = Vec::new();
        fin_vec.extend_from_slice(&fin_buf);
        let resp = crate::icd::decode_in_place::<Result<Response<'_>, ResponseError>>(&mut fin_vec)
            .unwrap();
        assert_eq!(resp, Ok(Response::Pong(1234)));
    }

    struct HwInner {
        last_flash_start: AtomicU32,
        last_flash_len: AtomicU32,
        last_erase_start: AtomicU32,
        last_erase_len: AtomicU32,
        last_settings_len: AtomicU32,
        last_settings_crc32: AtomicU32,
        last_read_start: AtomicU32,
        last_read_len: AtomicU32,
    }

    impl Default for HwInner {
        fn default() -> Self {
            Self {
                last_flash_start: AtomicU32::new(0xFFFF_FFFF),
                last_flash_len: AtomicU32::new(0xFFFF_FFFF),
                last_erase_start: AtomicU32::new(0xFFFF_FFFF),
                last_erase_len: AtomicU32::new(0xFFFF_FFFF),
                last_settings_len: AtomicU32::new(0xFFFF_FFFF),
                last_settings_crc32: AtomicU32::new(0xFFFF_FFFF),
                last_read_start: AtomicU32::new(0xFFFF_FFFF),
                last_read_len: AtomicU32::new(0xFFFF_FFFF),
            }
        }
    }

    struct AtomicHardware<'a> {
        inner: &'a HwInner,
        parameters: Parameters,
    }

    impl<'a> Flash for AtomicHardware<'a> {
        fn flash_range(&mut self, start: u32, data: &[u8]) {
            self.inner.last_flash_start.store(start, Ordering::Release);
            self.inner
                .last_flash_len
                .store(data.len() as u32, Ordering::Release);
        }

        fn erase_range(&mut self, start: u32, len: u32) {
            self.inner.last_erase_start.store(start, Ordering::Release);
            self.inner.last_erase_len.store(len, Ordering::Release);
        }

        fn write_settings(&mut self, data: &[u8], crc: u32) {
            self.inner
                .last_settings_len
                .store(data.len() as u32, Ordering::Release);
            self.inner.last_settings_crc32.store(crc, Ordering::Release);
        }

        fn read_range(&mut self, start_addr: u32, len: u32) -> &[u8] {
            self.inner
                .last_read_start
                .store(start_addr, Ordering::Release);
            self.inner.last_read_len.store(len, Ordering::Release);
            b"lolololol"
        }

        fn parameters(&self) -> &Parameters {
            &self.parameters
        }
    }
}
