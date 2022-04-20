use crate::enum_primitive::FromPrimitive;
use crate::stun_attr_value::{StunAttrType, StunAttrValue};
use crate::stun_const::MAGIC_COOKIE;
use byteorder::{BigEndian, ReadBytesExt};
use nom::bits::{
    bits,
    complete::{tag, take},
};
use nom::bytes::complete::take as byte_take;
use nom::combinator::map;
use nom::multi::{length_data, many0};
use nom::number::complete::be_u16;
use nom::sequence::tuple;
use nom::IResult;
use nom::{error::Error, error::ErrorKind::TagBits};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

/// A Stun attribute, https://tools.ietf.org/html/rfc5389#section-15
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Type                  |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Value (variable)                ....
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(PartialEq, Debug)]
pub struct StunAttribute {
    format: StunAttrType,
    value: StunAttrValue,
}

impl StunAttribute {
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Vec<StunAttribute>> {
        many0(map(
            tuple((byte_take(2usize), length_data(be_u16))),
            Self::to_stun_attribute,
        ))(input)
    }

    fn to_stun_attribute((fmt, val): (&[u8], &[u8])) -> StunAttribute {
        let fmt_arr: [u8; 2] = Self::clone_into_array(fmt);
        let fmt_num: u16 = u16::from_be_bytes(fmt_arr);
        let format = match StunAttrType::from_u16(fmt_num) {
            Some(f) => f,
            None => StunAttrType::UnknownAttributes,
        };
        let value = if Self::is_value(fmt_num) {
            StunAttrValue::Value(val.to_vec())
        } else if Self::is_attribute(fmt_num) {
            let (ip, port) = match Self::parse_addr(val) {
                Ok((_, r)) => r,
                Err(_) => (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            };
            StunAttrValue::Attr(ip, port)
        } else if Self::is_xattribute(fmt_num) {
            let (ip, port) = match Self::parse_xaddr(val) {
                Ok((_, r)) => r,
                Err(_) => (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            };
            StunAttrValue::XAttr(ip, port)
        } else if Self::is_change_req(fmt_num) {
            let code = match Self::parse_change_req(val) {
                Ok((_, r)) => r,
                Err(_) => 0,
            };
            StunAttrValue::Request(code)
        } else {
            // is_error_attribute
            let (code, reason) = match Self::parse_attr_err(val) {
                Ok((_, r)) => r,
                Err(_) => (0, "".to_string()),
            };
            StunAttrValue::ErrorAttr(code, reason)
        };
        StunAttribute { format, value }
    }

    fn is_value(format: u16) -> bool {
        match format {
            6..=8
            | 10..=13
            | 15
            | 16
            | 19..=21
            | 23..=26
            | 34
            | 36..=39
            | 42
            | 48
            | 32801
            | 32802
            | 32807..=32810
            | 49153
            | 49154 => true,
            _ => false,
        }
    }

    fn is_attribute(format: u16) -> bool {
        match format {
            1 | 2 | 4 | 5 | 14 | 17 | 32803 | 32811 | 32812 | 32848 => true,
            _ => false,
        }
    }

    fn is_xattribute(format: u16) -> bool {
        match format {
            18 | 22 | 32 | 40 | 32800 => true,
            _ => false,
        }
    }

    fn is_change_req(format: u16) -> bool {
        format == 3
    }

    fn is_error_attribute(format: u16) -> bool {
        format == 9
    }

    fn clone_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Clone,
    {
        let mut a = A::default();
        <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
        a
    }

    fn parse_addr(input: &[u8]) -> IResult<&[u8], (IpAddr, u16)> {
        let mut buf: &[u8] = &input[..8];
        match buf.read_u16::<BigEndian>().unwrap() {
            0x1 => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
                tuple((
                    tag(0x0, 8usize),
                    tag(0x1, 8usize),
                    take(16usize),
                    take(8usize),
                    take(8usize),
                    take(8usize),
                    take(8usize),
                )),
                |(_, _, port, i0, i1, i2, i3)| (IpAddr::V4(Ipv4Addr::new(i0, i1, i2, i3)), port),
            ))(input),
            0x2 => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
                tuple((
                    tag(0x0, 8usize),
                    tag(0x2, 8usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                    take(16usize),
                )),
                |(_, _, port, i0, i1, i2, i3, i4, i5, i6, i7)| {
                    (
                        IpAddr::V6(Ipv6Addr::new(i0, i1, i2, i3, i4, i5, i6, i7)),
                        port,
                    )
                },
            ))(input),
            _ => Err(nom::Err::Error(Error {
                input,
                code: TagBits,
            })),
        }
    }

    fn parse_xaddr(input: &[u8]) -> IResult<&[u8], (IpAddr, u16)> {
        let mut buf: &[u8] = &input[..8];
        match buf.read_u16::<BigEndian>().unwrap() {
            0x1 => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
                tuple((
                    tag(0x0, 8usize),
                    tag(0x1, 8usize),
                    take(16usize),
                    take(32usize),
                )),
                |(_, _, xport, xaddr): (_, _, u16, u32)| {
                    let xor_port = xport ^ (MAGIC_COOKIE >> 16) as u16;
                    let xor_ip = From::from(xaddr);
                    (IpAddr::V4(xor_ip), xor_port)
                },
            ))(input),
            0x2 => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
                tuple((
                    tag(0x0, 8usize),
                    tag(0x2, 8usize),
                    take(16usize),
                    take(128usize),
                )),
                |(_, _, xport, xaddr): (_, _, u16, u128)| {
                    let xor_port = xport ^ (MAGIC_COOKIE >> 16) as u16;
                    let xor_ip = From::from(xaddr);
                    (IpAddr::V6(xor_ip), xor_port)
                },
            ))(input),
            _ => Err(nom::Err::Error(Error {
                input,
                code: TagBits,
            })),
        }
    }

    fn parse_change_req(data: &[u8]) -> IResult<&[u8], u8> {
        bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
            tuple((take(29usize), take(2usize), take(1usize))),
            |(_, ip_port, _): (u32, u8, u8)| ip_port,
        ))(data)
    }

    fn parse_attr_err(data: &[u8]) -> IResult<&[u8], (u16, String)> {
        bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
            tuple((take(20usize), take(4usize), take(8usize))),
            |(_, cls, num): (u32, u16, u16)| {
                let class = cls & 15;
                let s = match str::from_utf8(data) {
                    Ok(v) => v,
                    Err(_) => "Invalid UTF-8 sequence",
                };
                (class * 100 + num, s.to_string())
            },
        ))(data)
    }
}

#[cfg(test)]
mod tests {
    use super::StunAttribute;
    use crate::stun_attr_value::{StunAttrType, StunAttrValue};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn extract_attrs_succeeds() {
        let bytes: &[u8] = &[
            0x00, 0x16, 0x00, 0x08, 0x00, 0x01, 0x4A, 0x86, 0x6B, 0x6F, 0x28, 0x17, 0x00, 0x20,
            0x00, 0x08, 0x00, 0x01, 0x3B, 0x13, 0x9D, 0x0F, 0x00, 0xBF, 0x00, 0x0D, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x14, 0xD2, 0x27, 0xB9, 0x81, 0xCE, 0x02,
            0xE6, 0x26, 0xF6, 0x79, 0xFA, 0xB3, 0x87, 0xC4, 0x99, 0x41, 0xE5, 0x11, 0x7F, 0x80,
        ];
        let res = StunAttribute::from_bytes(bytes);
        assert_eq!(
            res,
            Ok((
                &[][..],
                vec![
                    StunAttribute {
                        format: StunAttrType::XorRelayedAddress,
                        value: StunAttrValue::XAttr(
                            IpAddr::V4(Ipv4Addr::new(107, 111, 40, 23)),
                            27540
                        )
                    },
                    StunAttribute {
                        format: StunAttrType::XorMappedAddress,
                        value: StunAttrValue::XAttr(
                            IpAddr::V4(Ipv4Addr::new(157, 15, 0, 191)),
                            6657
                        )
                    },
                    StunAttribute {
                        format: StunAttrType::Lifetime,
                        value: StunAttrValue::Value([0, 0, 0, 120].to_vec())
                    },
                    StunAttribute {
                        format: StunAttrType::MessageIntegrity,
                        value: StunAttrValue::Value(
                            [
                                210, 39, 185, 129, 206, 2, 230, 38, 246, 121, 250, 179, 135, 196,
                                153, 65, 229, 17, 127, 128
                            ]
                            .to_vec()
                        )
                    }
                ]
            ))
        );
    }
}
