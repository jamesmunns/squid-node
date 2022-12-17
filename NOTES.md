Okay, I want a dumb little bootloader for the squid-node.

I'll use postcard for the line format.

I also probably want to have a settings page that can be managed from the bootloader. I'll probably use something like `[(&str, u32)]`.

* Page size: 2KiB
* Subpage size: 512B
* Smallest erase: Page (2KiB)


It'll be something like:

```
B->N: Cobs(Crc32(Req))
N->B: Cobs(Crc32(Result<Resp, RespErr>))
```

```rust
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
}

pub enum ResponseError {
    // StartBootload responses
    BadStartAddress,
    BadLength,

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
    }
}

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
}
```
