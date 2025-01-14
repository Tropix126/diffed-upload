use std::io::{self, Read};

/// VarIntProcessor encapsulates the logic for decoding a VarInt byte-by-byte.
#[derive(Default)]
pub struct VarIntProcessor {
    buf: [u8; 10],
    maxsize: usize,
    i: usize,
}

pub(crate) trait VarIntMaxSize {
    fn varint_max_size() -> usize;
}

impl<VI: VarInt> VarIntMaxSize for VI {
    fn varint_max_size() -> usize {
        (size_of::<VI>() * 8 + 7) / 7
    }
}

impl VarIntProcessor {
    fn new<VI: VarIntMaxSize>() -> VarIntProcessor {
        VarIntProcessor {
            maxsize: VI::varint_max_size(),
            ..VarIntProcessor::default()
        }
    }
    fn push(&mut self, b: u8) -> io::Result<()> {
        if self.i >= self.maxsize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unterminated varint",
            ));
        }
        self.buf[self.i] = b;
        self.i += 1;
        Ok(())
    }
    const fn finished(&self) -> bool {
        self.i > 0 && (self.buf[self.i - 1] & MSB == 0)
    }
    fn decode<VI: VarInt>(&self) -> Option<VI> {
        Some(VI::decode_var(&self.buf[0..self.i])?.0)
    }
}

pub const MSB: u8 = 0b1000_0000;
const DROP_MSB: u8 = 0b0111_1111;

/// A trait for reading VarInts from any other `Reader`.
///
/// It's recommended to use a buffered reader, as many small reads will happen.
pub trait VarIntReader {
    /// Returns either the decoded integer, or an error.
    ///
    /// In general, this always reads a whole varint. If the encoded varint's value is bigger
    /// than the valid value range of `VI`, then the value is truncated.
    ///
    /// On EOF, an io::Error with io::ErrorKind::UnexpectedEof is returned.
    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI>;
}

impl<R: Read> VarIntReader for R {
    fn read_varint<VI: VarInt>(&mut self) -> io::Result<VI> {
        let mut buf = [0_u8; 1];
        let mut p = VarIntProcessor::new::<VI>();

        while !p.finished() {
            let read = self.read(&mut buf)?;

            // EOF
            if read == 0 && p.i == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Reached EOF"));
            }
            if read == 0 {
                break;
            }

            p.push(buf[0])?;
        }

        p.decode()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Reached EOF"))
    }
}

/// Varint (variable length integer) encoding, as described in
/// https://developers.google.com/protocol-buffers/docs/encoding.
///
/// Uses zigzag encoding (also described there) for signed integer representation.
pub trait VarInt: Sized + Copy {
    /// Returns the number of bytes this number needs in its encoded form. Note: This varies
    /// depending on the actual number you want to encode.
    fn required_space(self) -> usize;
    /// Decode a value from the slice. Returns the value and the number of bytes read from the
    /// slice (can be used to read several consecutive values from a big slice)
    /// return None if all bytes has MSB set.
    fn decode_var(src: &[u8]) -> Option<(Self, usize)>;
    /// Encode a value into the slice. The slice must be at least `required_space()` bytes long.
    /// The number of bytes taken by the encoded integer is returned.
    fn encode_var(self, src: &mut [u8]) -> usize;
}

/// How many bytes an integer uses when being encoded as a VarInt.
#[inline]
const fn required_encoded_space_unsigned(mut v: u64) -> usize {
    if v == 0 {
        return 1;
    }

    let mut logcounter = 0;
    while v > 0 {
        logcounter += 1;
        v >>= 7;
    }
    logcounter
}

/// How many bytes an integer uses when being encoded as a VarInt.
#[inline]
const fn required_encoded_space_signed(v: i64) -> usize {
    required_encoded_space_unsigned(zigzag_encode(v))
}

#[inline]
const fn zigzag_encode(from: i64) -> u64 {
    ((from << 1) ^ (from >> 63)) as u64
}

// see: http://stackoverflow.com/a/2211086/56332
// casting required because operations like unary negation
// cannot be performed on unsigned integers
#[inline]
const fn zigzag_decode(from: u64) -> i64 {
    ((from >> 1) ^ (-((from & 1) as i64)) as u64) as i64
}

impl VarInt for u64 {
    fn required_space(self) -> usize {
        required_encoded_space_unsigned(self)
    }

    #[inline]
    fn decode_var(src: &[u8]) -> Option<(Self, usize)> {
        let mut result: u64 = 0;
        let mut shift = 0;

        let mut success = false;
        for b in src {
            let msb_dropped = b & DROP_MSB;
            result |= u64::from(msb_dropped) << shift;
            shift += 7;

            if b & MSB == 0 || shift > (9 * 7) {
                success = b & MSB == 0;
                break;
            }
        }

        if success {
            Some((result, shift / 7))
        } else {
            None
        }
    }

    #[inline]
    fn encode_var(self, dst: &mut [u8]) -> usize {
        debug_assert!(dst.len() >= self.required_space());
        let mut n = self;
        let mut i = 0;

        while n >= 0x80 {
            dst[i] = MSB | (n as u8);
            i += 1;
            n >>= 7;
        }

        dst[i] = n as u8;
        i + 1
    }
}

impl VarInt for i64 {
    fn required_space(self) -> usize {
        required_encoded_space_signed(self)
    }

    #[inline]
    fn decode_var(src: &[u8]) -> Option<(Self, usize)> {
        if let Some((result, size)) = u64::decode_var(src) {
            Some((zigzag_decode(result) as Self, size))
        } else {
            None
        }
    }

    #[inline]
    fn encode_var(self, dst: &mut [u8]) -> usize {
        debug_assert!(dst.len() >= self.required_space());
        let mut n: u64 = zigzag_encode(self);
        let mut i = 0;

        while n >= 0x80 {
            dst[i] = MSB | (n as u8);
            i += 1;
            n >>= 7;
        }

        dst[i] = n as u8;
        i + 1
    }
}

macro_rules! impl_varint {
    ($t:ty, unsigned) => {
        impl VarInt for $t {
            fn required_space(self) -> usize {
                required_encoded_space_unsigned(self as u64)
            }

            fn decode_var(src: &[u8]) -> Option<(Self, usize)> {
                let (n, s) = u64::decode_var(src)?;
                Some((n as Self, s))
            }

            fn encode_var(self, dst: &mut [u8]) -> usize {
                (self as u64).encode_var(dst)
            }
        }
    };
    ($t:ty, signed) => {
        impl VarInt for $t {
            fn required_space(self) -> usize {
                required_encoded_space_signed(self as i64)
            }

            fn decode_var(src: &[u8]) -> Option<(Self, usize)> {
                let (n, s) = i64::decode_var(src)?;
                Some((n as Self, s))
            }

            fn encode_var(self, dst: &mut [u8]) -> usize {
                (self as i64).encode_var(dst)
            }
        }
    };
}

impl_varint!(usize, unsigned);
impl_varint!(u32, unsigned);
