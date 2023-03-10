use core::ops::{Deref, DerefMut};

use crate::CRC;

use crate::icd::{
    encode_resp_to_slice, DataChunk, Parameters, Request, Response, ResponseError, StartBootload,
    Status, BootCommand,
};
use crc::Digest;
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
    len: usize,
}

impl<'acc, 'buf: 'acc> BorrowBuf<'acc, 'buf> {
    pub fn shrink_to(&mut self, size: usize) {
        if size < self.len {
            self.len = size;
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
        &self.acc.buffer[..self.len]
    }
}

impl<'acc, 'buf: 'acc> DerefMut for BorrowBuf<'acc, 'buf> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.acc.buffer[..self.len]
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
        BorrowBuf {
            len: self.buffer.len(),
            acc: self,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Bootable {
    Unsure,
    NoMagicFound,
    NoBadCrc,
    Yes,
}

pub trait Flash {
    fn flash_range(&mut self, start: u32, data: &[u8]);
    fn erase_range(&mut self, start: u32, len: u32);
    fn write_settings(&mut self, data: &[u8], crc: u32);
    fn read_range(&mut self, start_addr: u32, len: u32) -> &[u8];
    fn parameters(&self) -> &Parameters;
    fn boot(&mut self) -> !;

    fn is_bootable(&mut self) -> Bootable {
        let params = self.parameters();
        let (start, end) = params.valid_app_range;
        let chunk_len = params.data_chunk_size;

        let read_too_small = params.read_max < params.data_chunk_size;
        let not_one_page = end < (start.saturating_add(chunk_len));
        let page_too_small = chunk_len < 8;
        let backwards = end <= start;
        let fail_check = read_too_small || not_one_page || page_too_small || backwards;

        if fail_check {
            debug_assert!(false, "TODO: BYO is_bootable!");
            return Bootable::Unsure;
        }

        let magic = {
            let mut a_bytes = [0u8; 4];
            let mut b_bytes = [0u8; 4];
            let first_page = self.read_range(start, 8);
            a_bytes.copy_from_slice(&first_page[..4]);
            b_bytes.copy_from_slice(&first_page[4..8]);
            let a_word = u32::from_le_bytes(a_bytes);
            let b_word = u32::from_le_bytes(b_bytes);
            a_word.wrapping_mul(b_word)
        };

        // Do a first attempt, to attempt to find the magic number
        // at the end of a page
        let mut current = start;
        let mut magic_loc = None;
        while current < end {
            let cur_page = self.read_range(current, chunk_len);
            let mut magic_bytes = [0u8; 4];
            // Magic should be the SECOND TO LAST WORD in the range
            magic_bytes.copy_from_slice(&cur_page[(chunk_len - 8) as usize..(chunk_len - 4) as usize]);
            let magic_word = u32::from_le_bytes(magic_bytes);
            if magic_word == magic {
                magic_loc = Some(current);
                break;
            }
            current += chunk_len;
        }

        let last_page_start = match magic_loc {
            Some(lps) => lps,
            None => return Bootable::NoMagicFound,
        };

        // Okay, now go through, and checksum EVERYTHING
        let mut digest = CRC.digest();
        let mut current = start;
        while current < last_page_start {
            let cur_page = self.read_range(current, chunk_len);
            digest.update(cur_page);
            current += chunk_len;
        }
        let last_page = self.read_range(last_page_start, chunk_len);
        digest.update(&last_page[..(chunk_len - 4) as usize]);
        let act_crc = digest.finalize();
        let mut crc_bytes = [0u8; 4];
        crc_bytes.copy_from_slice(&last_page[(chunk_len - 4) as usize..]);
        let exp_crc = u32::from_le_bytes(crc_bytes);

        if act_crc == exp_crc {
            Bootable::Yes
        } else {
            Bootable::NoBadCrc
        }
    }

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
    BootPending,
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

    #[inline]
    pub fn push<'me>(&'me mut self, byte: u8) -> Option<BorrowBuf<'me, 'buf>> {
        let Machine { acc, state } = self;

        match acc.push(byte) {
            Ok(None) => None,
            Ok(Some(msg)) => {
                state.handle_msg(msg);
                Some(state.respond(acc.borrow_buf()))
            }
            Err(e) => {
                let mut buf = acc.borrow_buf();

                match encode_resp_to_slice(&Err(ResponseError::LineNak(e)), &mut buf) {
                    Ok(resp) => {
                        let len = resp.len();
                        buf.shrink_to(len);
                        Some(buf)
                    }
                    Err(_e) => None,
                }
            }
        }
    }

    pub fn check_after_send(&mut self) {
        if matches!(self.state.mode, Mode::BootPending) {
            self.state.hardware.boot();
        }
    }
}

impl<HW: Flash> State<HW> {
    #[inline]
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
                    Mode::BootLoad(meta) => {
                        response = Err(ResponseError::BootloadInProgress);
                        Mode::BootLoad(meta)
                    }
                    Mode::BootPending => {
                        response = Err(ResponseError::Oops);
                        Mode::BootPending
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
                    Mode::BootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::BootPending
                    }
                };
                response
            }
            Request::CompleteBootload { boot } => {
                let response;
                self.mode = match core::mem::replace(&mut self.mode, Mode::Idle) {
                    Mode::Idle => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::Idle
                    }
                    Mode::BootLoad(meta) => {
                        let (resp, mode) = self.handle_complete(meta, boot);
                        response = resp;
                        mode
                    }
                    Mode::BootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::BootPending
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
                    Mode::BootPending => Status::Idle,
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
                    Mode::BootPending => {
                        response = Err(ResponseError::NoBootloadActive);
                        Mode::BootPending
                    }
                };
                response
            }
            Request::IsBootable => {
                Ok(Response::BootableStatus(self.hardware.is_bootable()))
            },
            Request::Boot(cmd) => {
                let boot_status = self.hardware.is_bootable();
                let will_boot = match cmd {
                    BootCommand::BootIfBootable => boot_status == Bootable::Yes,
                    BootCommand::ForceBoot => true,
                };
                self.mode = Mode::BootPending;
                Ok(Response::ConfirmBootCmd {
                    will_boot,
                    boot_status,
                })
            },
        }
    }

    fn handle_complete(
        &mut self,
        meta: BootLoadMeta,
        boot_cmd: Option<BootCommand>,
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
                let boot_status = self.hardware.is_bootable();

                let will_boot = match boot_cmd {
                    Some(BootCommand::ForceBoot) => true,
                    Some(BootCommand::BootIfBootable) => boot_status == Bootable::Yes,
                    None => false,
                };

                response = Ok(Response::ConfirmComplete {
                    will_boot,
                    boot_status,
                });

                if will_boot {
                    Mode::BootPending
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

        let calc_crc = CRC.checksum(dc.data);
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
        let max_app_len = self.hardware.parameters().valid_app_range.1
            - self.hardware.parameters().valid_app_range.0;
        let too_long = sb.length > max_app_len;
        let mask = self.hardware.parameters().data_chunk_size - 1;
        let not_full = (sb.length & mask) != 0;
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

    #[inline]
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
    use crate::{
        icd::{
            decode_in_place, DataChunk, Parameters, Request, Response, ResponseError, StartBootload,
        },
        machine::{stm32g031_params, Accumulator, Machine, Mode, Bootable}, CRC,
    };
    use std::sync::{Arc, Mutex};

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
        let hw = AtomicHardware::new(stm32g031_params());

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
        flash: Vec<u8>,
        settings: Vec<u8>,
    }

    #[derive(Clone)]
    struct AtomicHardware {
        inner: Arc<Mutex<HwInner>>,
        parameters: Parameters,
    }

    impl AtomicHardware {
        pub fn new(params: Parameters) -> Self {
            assert_eq!(params.valid_flash_range.0, 0);
            Self {
                inner: Arc::new(Mutex::new(HwInner {
                    flash: vec![0xA5u8; params.valid_flash_range.1 as usize],
                    settings: vec![0xCCu8; 4usize + params.settings_max as usize],
                })),
                parameters: params,
            }
        }
    }

    impl Flash for AtomicHardware {
        fn flash_range(&mut self, start: u32, data: &[u8]) {
            assert_eq!(self.parameters.valid_flash_range.0, 0);
            let mut inner = self.inner.lock().unwrap();
            let su = start as usize;
            let range = inner.flash.get_mut(su..su + data.len()).unwrap();

            range
                .iter()
                .for_each(|b| assert_eq!(*b, 0xFF, "flash not erased!"));
            range.copy_from_slice(data)
        }

        fn erase_range(&mut self, start: u32, len: u32) {
            assert_eq!(self.parameters.valid_flash_range.0, 0);
            let mut inner = self.inner.lock().unwrap();
            let su = start as usize;
            let lu = len as usize;
            inner
                .flash
                .get_mut(su..su + lu)
                .unwrap()
                .iter_mut()
                .for_each(|b| *b = 0xFF);
        }

        fn write_settings(&mut self, data: &[u8], crc: u32) {
            let mut inner = self.inner.lock().unwrap();
            inner
                .settings
                .get_mut(..data.len())
                .unwrap()
                .copy_from_slice(data);
            inner
                .settings
                .get_mut(data.len()..data.len() + 4)
                .unwrap()
                .copy_from_slice(&crc.to_le_bytes());
        }

        fn read_range(&mut self, start: u32, len: u32) -> &[u8] {
            assert_eq!(self.parameters.valid_flash_range.0, 0);
            let mut inner = self.inner.lock().unwrap();
            let su = start as usize;
            let lu = len as usize;
            let vec = inner
                .flash
                .get(su..su + lu)
                .unwrap()
                .to_vec();

            // This is: uh, not great.
            vec.leak()
        }

        fn parameters(&self) -> &Parameters {
            &self.parameters
        }

        fn boot(&mut self) -> ! {
            todo!()
        }
    }

    #[test]
    fn do_a_bootload() {
        // Create a fake (in-memory) hardware impl
        let hw = AtomicHardware::new(stm32g031_params());

        // Create the bootload "server": this usually runs on-device
        let mut acc_buf = [0u8; 3 * 1024];
        let mut machine = Machine::new(&mut acc_buf, hw.clone());

        let last = {
            let mut last = vec![22; 2040];
            let magic = 0x10101010u32.wrapping_mul(0x10101010u32);
            last.extend_from_slice(&magic.to_le_bytes());
            last.extend_from_slice(&0x4F54_CCBCu32.to_le_bytes());
            last.leak()
        };

        // The sequence of commands sent and expected responses
        let seq: &[(Request<'static>, Result<Response<'static>, ResponseError>)] = &[
            (
                Request::GetParameters,
                Ok(Response::Parameters(stm32g031_params())),
            ),
            (
                Request::IsBootable,
                Ok(Response::BootableStatus(Bootable::NoMagicFound))
            ),
            (
                Request::StartBootload(StartBootload {
                    start_addr: 16 * 1024,
                    length: 8 * 1024,
                    crc32: 0x51f3_6231,
                }),
                Ok(Response::BootloadStarted),
            ),
            (
                Request::DataChunk(DataChunk {
                    data_addr: 16 * 1024,
                    sub_crc32: 0x5b54_dab5,
                    data: &[16; 2048],
                }),
                Ok(Response::ChunkAccepted {
                    data_addr: 16 * 1024,
                    data_len: 2048,
                    crc32: 0x5b54_dab5,
                }),
            ),
            (
                Request::DataChunk(DataChunk {
                    data_addr: 18 * 1024,
                    sub_crc32: 0x8c91_77aa,
                    data: &[18; 2048],
                }),
                Ok(Response::ChunkAccepted {
                    data_addr: 18 * 1024,
                    data_len: 2048,
                    crc32: 0x8c91_77aa,
                }),
            ),
            (
                Request::DataChunk(DataChunk {
                    data_addr: 20 * 1024,
                    sub_crc32: 0xf01e_9d3c,
                    data: &[20; 2048],
                }),
                Ok(Response::ChunkAccepted {
                    data_addr: 20 * 1024,
                    data_len: 2048,
                    crc32: 0xf01e_9d3c,
                }),
            ),
            (
                Request::DataChunk(DataChunk {
                    data_addr: 22 * 1024,
                    sub_crc32: 0x514d5248,
                    data: last,
                }),
                Ok(Response::ChunkAccepted {
                    data_addr: 22 * 1024,
                    data_len: 2048,
                    crc32: 0x514d5248,
                }),
            ),
            (
                Request::CompleteBootload { boot: None },
                Ok(Response::ConfirmComplete { will_boot: false, boot_status: Bootable::Yes }),
            ),
        ];

        for (req, exp_res) in seq {
            // Encode the message to a vec, but throw away the last byte
            // so we can trigger that manually
            let mut enc_used = req.encode_to_vec();
            enc_used.pop();

            // Push all, make sure no response, then push the final one
            for b in enc_used {
                let res = machine.push(b);
                assert!(matches!(res, None));
            }
            let res = machine.push(0x00);

            // Did we get a response, and is it the expected response?
            let mut res = res.unwrap();
            let act_res: Result<Response<'_>, ResponseError> = decode_in_place(&mut res).unwrap();
            assert_eq!(&act_res, exp_res);

            // Does the accumulator reset?
            drop(act_res);
            drop(res);
            assert_eq!(machine.acc.idx, 0);
        }

        // Memory test!
        {
            let hwinner = hw.inner.lock().unwrap();
            let flash = &hwinner.flash;

            // Unprogrammed regions
            assert_eq!(&flash[..16 * 1024], [0xA5; 16 * 1024].as_slice());
            assert_eq!(&flash[24 * 1024..], [0xA5; (64 - 24) * 1024].as_slice());

            // Programmed regions
            assert_eq!(&flash[16 * 1024..][..2048], [16; 2048].as_slice());
            assert_eq!(&flash[18 * 1024..][..2048], [18; 2048].as_slice());
            assert_eq!(&flash[20 * 1024..][..2048], [20; 2048].as_slice());
            assert_eq!(&flash[22 * 1024..][..2048], last);
        }

        // We commanded NO reboot after flashing
        assert!(matches!(machine.state.mode, Mode::Idle));
    }

}
