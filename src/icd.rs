use crc::Digest;
use postcard::ser_flavors::{Cobs, Slice, StdVec};
use serde::{Deserialize, Serialize};

use crate::CRC;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DataChunk<'a> {
    pub data_addr: u32,
    pub sub_crc32: u32,
    pub data: &'a [u8],
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StartBootload {
    pub start_addr: u32,
    pub length: u32,
    pub crc32: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Request<'a> {
    Ping(u32),
    GetParameters,
    // -=-=-=-=-=-=-=- DON'T REORDER ABOVE HERE -=-=-=-=-=-=-=- //
    StartBootload(StartBootload),
    DataChunk(DataChunk<'a>),
    CompleteBootload { reboot: bool },
    GetSettings,
    WriteSettings { crc32: u32, data: &'a [u8] },
    GetStatus,
    ReadRange { start_addr: u32, len: u32 },
    AbortBootload,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseError {
    // StartBootload responses
    BadStartAddress,
    BadLength,
    BootloadInProgress,

    // DataChunk responses
    SkippedRange { expected: u32, actual: u32 },
    IncorrectLength { expected: u32, actual: u32 },
    BadSubCrc { expected: u32, actual: u32 },
    NoBootloadActive,
    TooManyChunks,

    // CompleteBootload responses
    IncompleteLoad { expected_len: u32, actual_len: u32 },
    BadFullCrc { expected: u32, actual: u32 },

    // WriteSettings
    SettingsTooLong { max: u32, actual: u32 },
    BadSettingsCrc { expected: u32, actual: u32 },

    // ReadRange
    BadRangeStart,
    BadRangeEnd,
    BadRangeLength { actual: u32, max: u32 },

    LineNak(crate::machine::Error),
    Oops,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Status {
    Idle,
    Started {
        start_addr: u32,
        length: u32,
        crc32: u32,
    },
    Loading {
        start_addr: u32,
        next_addr: u32,
        partial_crc32: u32,
        expected_crc32: u32,
    },
    AwaitingComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    pub settings_max: u32,
    pub data_chunk_size: u32,
    pub valid_flash_range: (u32, u32),
    pub valid_app_range: (u32, u32),
    pub read_max: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Response<'a> {
    Pong(u32),
    Parameters(Parameters),
    // -=-=-=-=-=-=-=- DON'T REORDER ABOVE HERE -=-=-=-=-=-=-=- //
    BootloadStarted,
    ChunkAccepted {
        data_addr: u32,
        data_len: u32,
        crc32: u32,
    },
    ConfirmComplete {
        will_reboot: bool,
    },
    Settings {
        data: &'a [u8],
        crc32: u32,
    },
    SettingsAccepted {
        data_len: u32,
        crc32: u32,
    },
    Status(Status),
    ReadRange {
        start_addr: u32,
        len: u32,
        data: &'a [u8],
    },
    BadOverfillNak,
    BadPostcardNak,
    BadCrcNak,
    BootloadAborted,
}

#[cfg(feature = "use-std")]
impl<'a> Request<'a> {
    /// Encode a request to a vec.
    ///
    /// Does:
    ///
    /// * postcard encoding
    /// * appending crc32 (le)
    /// * cobs encoding
    /// * DOES append `0x00` terminator
    pub fn encode_to_vec(&self) -> Vec<u8> {
        postcard::serialize_with_flavor::<Self, Crc32SerFlavor<Cobs<StdVec>>, Vec<u8>>(
            self,
            Crc32SerFlavor {
                flav: Cobs::try_new(StdVec::new()).unwrap(),
                checksum: CRC.digest(),
            },
        )
        .unwrap()
    }
}

#[cfg(feature = "use-std")]
impl<'a> Response<'a> {
    /// Encode a request to a vec.
    ///
    /// Does:
    ///
    /// * postcard encoding
    /// * appending crc32 (le)
    /// * cobs encoding
    /// * DOES append `0x00` terminator
    pub fn encode_to_vec(&self) -> Vec<u8> {
        postcard::serialize_with_flavor::<Self, Crc32SerFlavor<Cobs<StdVec>>, Vec<u8>>(
            self,
            Crc32SerFlavor {
                flav: Cobs::try_new(StdVec::new()).unwrap(),
                checksum: CRC.digest(),
            },
        )
        .unwrap()
    }
}

pub fn encode_resp_to_slice<'a, 'b>(
    resp: &Result<Response<'a>, ResponseError>,
    buf: &'b mut [u8],
) -> Result<&'b mut [u8], postcard::Error> {
    postcard::serialize_with_flavor::<
        Result<Response<'a>, ResponseError>,
        Crc32SerFlavor<Cobs<Slice<'b>>>,
        &'b mut [u8],
    >(
        &resp,
        Crc32SerFlavor {
            flav: Cobs::try_new(Slice::new(buf))?,
            checksum: CRC.digest(),
        },
    )
}

#[inline]
pub fn decode_in_place<'a, T: Deserialize<'a>>(
    buf: &'a mut [u8],
) -> Result<T, crate::machine::Error> {
    let used = cobs::decode_in_place(buf).map_err(|_| crate::machine::Error::Cobs)?;
    let buf = buf
        .get_mut(..used)
        .ok_or(crate::machine::Error::LogicError)?;
    if used < 5 {
        return Err(crate::machine::Error::Underfill);
    }
    let (data, crc) = buf.split_at_mut(used - 4);
    let mut crc_bytes = [0u8; 4];
    crc_bytes.copy_from_slice(crc);
    let exp_crc = u32::from_le_bytes(crc_bytes);
    let act_crc = CRC.checksum(data);
    if exp_crc != act_crc {
        return Err(crate::machine::Error::Crc {
            expected: exp_crc,
            actual: act_crc,
        });
    }
    postcard::from_bytes(data).map_err(|_| crate::machine::Error::PostcardDecode)
}

struct Crc32SerFlavor<B>
where
    B: postcard::ser_flavors::Flavor,
{
    flav: B,
    checksum: Digest<'static, u32>,
}

impl<B> postcard::ser_flavors::Flavor for Crc32SerFlavor<B>
where
    B: postcard::ser_flavors::Flavor,
{
    type Output = <B as postcard::ser_flavors::Flavor>::Output;

    #[inline]
    fn try_push(&mut self, data: u8) -> postcard::Result<()> {
        self.checksum.update(&[data]);
        self.flav.try_push(data)
    }

    #[inline]
    fn finalize(mut self) -> postcard::Result<Self::Output> {
        let calc_crc = self.checksum.finalize();
        self.flav.try_extend(&calc_crc.to_le_bytes())?;
        self.flav.finalize()
    }

    #[inline]
    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        self.checksum.update(data);
        self.flav.try_extend(data)
    }
}
