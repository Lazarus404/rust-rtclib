use crate::stun_const::MAGIC_COOKIE;
use bytes::{BufMut, Bytes, BytesMut};
use nom::bits::{bits, complete::tag, streaming::take};
use nom::combinator::map;
use nom::error::Error;
use nom::sequence::tuple;
use nom::{IResult, Needed};

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
    class: u8,
    method: u16,
    length: u16,
    transaction_id: u128,
}

impl StunHeader {
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], StunHeader> {
        if input.len() < 20 {
            // binary header should be 20 bytes
            Err(nom::Err::Incomplete(Needed::new(20)))
        } else {
            bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
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
                    let method = (m0 << 7) | (m1 << 4) | m2;
                    let class = (c0 << 1) | c1;
                    StunHeader {
                        method,
                        class,
                        length,
                        transaction_id,
                    }
                },
            ))(input)
        }
    }

    pub fn to_bytes(header: StunHeader) -> Bytes {
        // position elements in 16 bit width
        let m0: u16 = (header.method & 0xF80) << 2;
        let m1: u16 = (header.method & 0x70) << 1;
        let m2: u16 = header.method & 0xF;
        let c0: u16 = ((header.class as u16) & 0x2) << 7;
        let c1: u16 = ((header.class as u16) & 0x1) << 4;
        // combine elements to new 16 bit value
        let leading: u16 = m0 | c0 | m1 | c1 | m2;
        // extract 96 bits to 64 bit unsigned and 32 bit unsigned respectively
        let trans1: u64 = (header.transaction_id >> 32) as u64;
        let trans2: u32 = (header.transaction_id & 0xFFFFFFFF) as u32;
        // convert values to byte array
        let mut buf = BytesMut::with_capacity(20);
        buf.put_u16(leading);
        buf.put_u16(header.length);
        buf.put_u32(MAGIC_COOKIE);
        buf.put_u64(trans1);
        buf.put_u32(trans2);
        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::StunHeader;
    use nom::error::{Error, ErrorKind::TagBits};
    use nom::Needed;

    #[test]
    fn extract_header_succeeds() {
        let bytes: &[u8] = &[
            0u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8, 163u8,
            87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let res = StunHeader::from_bytes(bytes);
        let (rest, header) = match res {
            Ok((rest, header)) => (rest, header),
            Err(_) => (
                &[0][..],
                StunHeader {
                    class: 0,
                    method: 0,
                    length: 0,
                    transaction_id: 0,
                },
            ),
        };
        assert_eq!(
            header,
            StunHeader {
                class: 0,
                method: 1,
                length: 0,
                transaction_id: 177565706535525809372192520
            }
        );
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn extract_invalid_header_fails() {
        let bad_bytes: &[u8] = &[
            255u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let res = StunHeader::from_bytes(bad_bytes);
        assert_eq!(
            res,
            Err(nom::Err::Error(Error {
                input: bad_bytes,
                code: TagBits
            }))
        );
    }

    #[test]
    fn extract_too_short_header_fails() {
        let bad_bytes: &[u8] = &[
            255u8, 1u8, 0u8, 0u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8,
        ];
        let res = StunHeader::from_bytes(bad_bytes);
        assert_eq!(res, Err(nom::Err::Incomplete(Needed::new(20))));
    }

    #[test]
    fn serialise_header_succeeds() {
        let bytes: &[u8] = &[
            62u8, 239u8, 90u8, 90u8, 33u8, 18u8, 164u8, 66u8, 0u8, 146u8, 225u8, 0u8, 61u8, 62u8,
            163u8, 87u8, 45u8, 150u8, 223u8, 8u8,
        ];
        let header = StunHeader {
            class: 0,
            method: 4095,
            length: 23130,
            transaction_id: 177565706535525809372192520,
        };
        assert_eq!(&StunHeader::to_bytes(header)[..], bytes);
    }
}
