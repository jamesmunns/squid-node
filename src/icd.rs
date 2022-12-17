use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Request<'a> {
    Ping(u32),
    GetParameters,
    // -=-=-=-=-=-=-=- DON'T REORDER ABOVE HERE -=-=-=-=-=-=-=- //
    StartBootload {
        start_addr: u32,
        length: u32,
        crc32: u32,
    },
    DataChunk {
        data_addr: u32,
        sub_crc32: u32,
        data: &'a [u8],
    },
    CompleteBootload {
        reboot: bool,
    },
    GetSettings,
    WriteSettings {
        crc32: u32,
        data: &'a [u8],
    },
    GetStatus,
    ReadRange {
        start_addr: u32,
        len: u32,
    },
    AbortBootload,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseError {
    // StartBootload responses
    BadStartAddress,
    BadLength,
    BootloadInProgress,

    // DataChunk responses
    SkippedRange {
        expected: u32,
        actual: u32,
    },
    IncorrectLength {
        expected: u32,
        actual: u32,
    },
    BadSubCrc {
        expected: u32,
        actual: u32,
    },
    NoBootloadActive,
    TooManyChunks,

    // CompleteBootload responses
    IncompleteLoad {
        expected_len: u32,
        actual_len: u32,
    },
    BadFullCrc {
        expected: u32,
        actual: u32,
    },

    // WriteSettings
    SettingsTooLong {
        max: u32,
        actual: u32,
    },
    BadSettingsCrc {
        expected: u32,
        actual: u32,
    },

    // ReadRange
    BadRangeStart,
    BadRangeEnd,
    BadRangeLength {
        actual: u32,
        max: u32,
    },

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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Response<'a> {
    Pong(u32),
    Parameters {
        settings_max: u32,
        data_chunk_size: u32,
        valid_ram_read: (u32, u32),
        valid_flash_read: (u32, u32),
        read_max: u32,
    },
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
        use crc::{CRC_32_CKSUM, Crc};

        let mut used = postcard::to_stdvec(self).unwrap();

        let crcr = Crc::<u32>::new(&CRC_32_CKSUM);
        let act_crc = crcr.checksum(&used);
        used.extend_from_slice(&act_crc.to_le_bytes());
        let mut enc_used = cobs::encode_vec(&used);
        // Terminator
        enc_used.push(0x00);

        enc_used
    }
}
