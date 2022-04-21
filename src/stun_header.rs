use crate::enum_primitive::FromPrimitive;
use crate::stun_const::MAGIC_COOKIE;
use crate::stun_error::StunError;
use crate::stun_type::{StunClass, StunMethod};
use bytes::{BufMut, Bytes, BytesMut};
use nom::bits::{bits, complete::tag, streaming::take};
use nom::combinator::map;
use nom::error::Error;
use nom::sequence::tuple;

/// A STUN packet, https://tools.ie
/// tf.org/html/rfc5389#page-10
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0|     STUN Message Type     |         Message Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Magic Cookie                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                     Transaction ID (96 bits)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(PartialEq, Debug)]
pub struct StunHeader {
    pub class: StunClass,
    pub method: StunMethod,
    pub length: u16,
    pub transaction_id: u128,
}

/// accepts a stream of bytes and may return a tuple where
/// the first element is the remaining bytes and the second
/// element contains the decoded STUN header
pub fn from_bytes(input: &[u8]) -> Result<(&[u8], StunHeader), StunError> {
    if input.len() < 20 {
        // binary header should be 20 bytes
        Err(StunError::Incomplete(20))
    } else {
        match bits::<_, _, Error<(&[u8], usize)>, Error<&[u8]>, _>(map(
            tuple((
                tag(0x00, 2usize),
                take(5usize),
                take(1usize),
                take(3usize),
                take(1usize),
                take(4usize),
                take(16usize),
                tag(MAGIC_COOKIE, 32usize),
                take(96usize),
            )),
            |(_stun, m0, c0, m1, c1, m2, length, _cookie, transaction_id): (
                _,
                u16,
                u8,
                u16,
                u8,
                u16,
                u16,
                u32,
                u128,
            )| {
                let method = match StunMethod::from_u16((m0 << 7) | (m1 << 4) | m2) {
                    Some(m) => m,
                    None => StunMethod::Binding,
                };
                let class = match StunClass::from_u8((c0 << 1) | c1) {
                    Some(c) => c,
                    None => StunClass::Request,
                };
                StunHeader {
                    method,
                    class,
                    length,
                    transaction_id,
                }
            },
        ))(input)
        {
            Ok(h) => Ok(h),
            Err(_) => Err(StunError::Invalid),
        }
    }
}

impl StunHeader {
    pub fn to_bytes(self) -> Bytes {
        // position elements in 16 bit width
        let method = self.method as u16;
        let class = self.class as u16;
        let m0: u16 = (method & 0xF80) << 2;
        let m1: u16 = (method & 0x70) << 1;
        let m2: u16 = method & 0xF;
        let c0: u16 = ((class as u16) & 0x2) << 7;
        let c1: u16 = ((class as u16) & 0x1) << 4;
        // combine elements to new 16 bit value
        let leading: u16 = m0 | c0 | m1 | c1 | m2;
        // extract 96 bits to 64 bit unsigned and 32 bit unsigned respectively
        let trans1: u64 = (self.transaction_id >> 32) as u64;
        let trans2: u32 = (self.transaction_id & 0xFFFFFFFF) as u32;
        // convert values to byte array
        let mut buf = BytesMut::with_capacity(20);
        buf.put_u16(leading);
        buf.put_u16(self.length);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_u64(trans1);
        buf.put_u32(trans2);
        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::StunHeader;
    use crate::stun_error::StunError;
    use crate::stun_type::{StunClass, StunMethod};

    #[test]
    fn extract_header_succeeds() {
        let bytes: &[u8] = &[
            0u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8, 163u8,
            87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let res = super::from_bytes(bytes);
        let header = match res {
            Ok((_, header)) => header,
            Err(_) => StunHeader {
                class: StunClass::Success,
                method: StunMethod::Refresh,
                length: 0,
                transaction_id: 0,
            },
        };
        assert_eq!(
            header,
            StunHeader {
                class: StunClass::Request,
                method: StunMethod::Binding,
                length: 0,
                transaction_id: 177565706535525809372192520
            }
        );
    }

    #[test]
    fn extract_invalid_header_fails() {
        let bad_bytes: &[u8] = &[
            255u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let res = super::from_bytes(bad_bytes);
        assert_eq!(res, Err(StunError::Invalid));
    }

    #[test]
    fn extract_too_short_header_fails() {
        let bad_bytes: &[u8] = &[
            255u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8,
        ];
        let res = super::from_bytes(bad_bytes);
        assert_eq!(res, Err(StunError::Incomplete(20)));
    }

    #[test]
    fn serialise_header_succeeds() {
        let bytes: &[u8] = &[
            0u8, 1u8, 90u8, 90u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let header = StunHeader {
            class: StunClass::Request,
            method: StunMethod::Binding,
            length: 23130,
            transaction_id: 177565706535525809372192520,
        };
        assert_eq!(&header.to_bytes()[..], bytes);
    }
}
