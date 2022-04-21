use crate::enum_primitive::FromPrimitive;
use crate::stun_const::MAGIC_COOKIE;
use crate::stun_error::StunError;
use crate::stun_type::{StunAttrType, StunAttrValue};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use nom::bits::{
    bits,
    complete::{tag, take},
};
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
use nom::{error::Error, error::ErrorKind::TagBits};
use std::cmp::min;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use std::vec::Vec;

/// A Stun attribute, https://tools.ietf.org/html/rfc5389#section-15
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Type                  |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Value (variable)                ....
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Clone, PartialEq, Debug)]
pub struct StunAttribute {
    pub format: StunAttrType,
    pub value: StunAttrValue,
}

pub fn from_bytes(input: &[u8], length: u16) -> Result<(&[u8], Vec<StunAttribute>), StunError> {
    if input.len() < 4 || (input.len() as u16) < length {
        return Err(StunError::Incomplete(4));
    }
    let mut indx: usize = 0;
    let mut attrs: Vec<StunAttribute> = Vec::new();
    while (indx as u16) < length {
        let fmt = &input[indx..indx + 2];
        let len_bytes = &input[indx + 2..indx + 4];
        let len_arr: [u8; 2] = clone_into_array(len_bytes);
        let len = min(u16::from_be_bytes(len_arr), length - (indx as u16) - 1);
        let needed = (4 - (len % 4)) % 4;
        let val = &input[indx + 4..(indx + 4 + (len as usize))];
        attrs.push(to_stun_attribute(fmt, val));
        indx += 4 + ((len + needed) as usize);
    }
    Ok((&input[indx..], attrs))
}

pub fn to_bytes(attrs: &Vec<StunAttribute>) -> Bytes {
    let mut total_bytes: usize = 0;
    let bin_attrs: Vec<_> = attrs
        .iter()
        .map(|attr| {
            let fmt = attr.format as u16;
            let parsed_attrs: Bytes = match &attr.value {
                StunAttrValue::Value(vec) => encode_value(vec),
                StunAttrValue::Attr(ip, port) => encode_addr(ip, (0 + port) as u16),
                StunAttrValue::XAttr(ip, port) => encode_xaddr(ip, (0 + port) as u16),
                StunAttrValue::Request(code) => encode_change_req(code),
                StunAttrValue::ErrorAttr(code, reason) => encode_attr_err(code, reason),
            };
            total_bytes += (parsed_attrs.len() + 4) as usize;
            (fmt, parsed_attrs)
        })
        .collect();
    let mut buf = BytesMut::with_capacity(total_bytes as usize);
    for (fmt, attr) in bin_attrs {
        buf.put_u16(fmt);
        let len = attr.len() as u16;
        buf.put_u16(len);
        buf.put_slice(&attr[..]);
        if len % 4 > 0 {
            let needed = (4 - (len % 4)) % 4;
            for _ in 0..needed {
                buf.put_u8(0);
            }
        }
    }
    buf.freeze()
}

pub fn to_stun_attribute(fmt: &[u8], val: &[u8]) -> StunAttribute {
    let fmt_arr: [u8; 2] = clone_into_array(fmt);
    let fmt_num: u16 = u16::from_be_bytes(fmt_arr);
    let format = match StunAttrType::from_u16(fmt_num) {
        Some(f) => f,
        None => StunAttrType::UnknownAttributes,
    };
    let value = if is_value(fmt_num) {
        StunAttrValue::Value(val.to_vec())
    } else if is_attribute(fmt_num) {
        let (_, (ip, port)) = decode_addr(val)
            .unwrap_or_else(|_| (&[][..], (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));
        StunAttrValue::Attr(ip, port)
    } else if is_xattribute(fmt_num) {
        let (_, (ip, port)) = decode_xaddr(val)
            .unwrap_or_else(|_| (&[][..], (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));
        StunAttrValue::XAttr(ip, port)
    } else if is_change_req(fmt_num) {
        let (_, code) = decode_change_req(val).unwrap_or_else(|_| (&[][..], 0));
        StunAttrValue::Request(code)
    } else {
        // is_error_attribute
        let (_, (code, reason)) =
            decode_attr_err(val).unwrap_or_else(|_| (&[][..], (0, "".to_string())));
        StunAttrValue::ErrorAttr(code, reason)
    };
    StunAttribute { format, value }
}

pub fn is_value(format: u16) -> bool {
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

pub fn is_attribute(format: u16) -> bool {
    match format {
        1 | 2 | 4 | 5 | 14 | 17 | 32803 | 32811 | 32812 | 32848 => true,
        _ => false,
    }
}

pub fn is_xattribute(format: u16) -> bool {
    match format {
        18 | 22 | 32 | 40 | 32800 => true,
        _ => false,
    }
}

pub fn is_change_req(format: u16) -> bool {
    format == 3
}

pub fn is_error_attribute(format: u16) -> bool {
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

fn encode_value(vec: &Vec<u8>) -> Bytes {
    let mut buf = BytesMut::with_capacity(vec.len());
    buf.put_slice(&vec[..]);
    buf.freeze()
}

fn decode_addr(input: &[u8]) -> IResult<&[u8], (IpAddr, u16)> {
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

fn encode_addr(addr: &IpAddr, port: u16) -> Bytes {
    match addr {
        IpAddr::V4(ip4) => {
            let mut buf = BytesMut::with_capacity(8);
            buf.put_u16(0x01);
            buf.put_u16(port);
            buf.put_slice(&ip4.octets());
            buf.freeze()
        }
        IpAddr::V6(ip6) => {
            let mut buf = BytesMut::with_capacity(20);
            buf.put_u16(0x02);
            buf.put_u16(port);
            buf.put_slice(&ip6.octets());
            buf.freeze()
        }
    }
}

fn decode_xaddr(input: &[u8]) -> IResult<&[u8], (IpAddr, u16)> {
    let mut buf: &[u8] = &input[..2];
    match buf.read_u16::<BigEndian>() {
        Ok(0x1) => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
            tuple((
                tag(0x0, 8usize),
                tag(0x1, 8usize),
                take(16usize),
                take(32usize),
            )),
            |(_, _, xport, xaddr): (_, _, u16, u32)| {
                let xor_port = xport ^ (MAGIC_COOKIE >> 16) as u16;
                let xor_ip_u32 = xaddr ^ MAGIC_COOKIE as u32;
                let xor_ip = Ipv4Addr::new(
                    (xor_ip_u32 >> 24) as u8,
                    (xor_ip_u32 >> 16) as u8,
                    (xor_ip_u32 >> 8) as u8,
                    xor_ip_u32 as u8,
                );
                (IpAddr::V4(xor_ip), xor_port)
            },
        ))(input),
        Ok(0x2) => bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
            tuple((
                tag(0x0, 8usize),
                tag(0x2, 8usize),
                take(16usize),
                take(128usize),
            )),
            |(_, _, xport, xaddr): (_, _, u16, u128)| {
                let xor_port = xport ^ (MAGIC_COOKIE >> 16) as u16;
                let xor_ip_u128 = xaddr ^ MAGIC_COOKIE as u128;
                let xor_ip = Ipv6Addr::new(
                    (xor_ip_u128 >> 112) as u16,
                    (xor_ip_u128 >> 96) as u16,
                    (xor_ip_u128 >> 80) as u16,
                    (xor_ip_u128 >> 64) as u16,
                    (xor_ip_u128 >> 48) as u16,
                    (xor_ip_u128 >> 32) as u16,
                    (xor_ip_u128 >> 16) as u16,
                    xor_ip_u128 as u16,
                );
                (IpAddr::V6(xor_ip), xor_port)
            },
        ))(input),
        _ => Err(nom::Err::Error(Error {
            input,
            code: TagBits,
        })),
    }
}

fn encode_xaddr(addr: &IpAddr, port: u16) -> Bytes {
    let xport: u16 = port ^ (MAGIC_COOKIE >> 16) as u16;
    match addr {
        IpAddr::V4(ip4) => {
            let mut buf = BytesMut::with_capacity(8);
            let ip = ip4.octets();
            let ip32: u32 = (((ip[0] as u32) << 24)
                + ((ip[1] as u32) << 16)
                + ((ip[2] as u32) << 8)
                + (ip[3] as u32)) as u32;
            let xor_ip32 = ip32 ^ MAGIC_COOKIE as u32;
            buf.put_slice(&[
                0x0 as u8,
                0x1 as u8,
                (xport >> 8) as u8,
                xport as u8,
                (xor_ip32 >> 24) as u8,
                (xor_ip32 >> 16) as u8,
                (xor_ip32 >> 8) as u8,
                xor_ip32 as u8,
            ]);
            buf.freeze()
        }
        IpAddr::V6(ip6) => {
            let mut buf = BytesMut::with_capacity(20);
            let ip = ip6.octets();
            let ip128: u128 = ((ip[0] as u128) << 120)
                + ((ip[1] as u128) << 112)
                + ((ip[2] as u128) << 104)
                + ((ip[3] as u128) << 96)
                + ((ip[4] as u128) << 88)
                + ((ip[5] as u128) << 80)
                + ((ip[6] as u128) << 72)
                + ((ip[7] as u128) << 64)
                + ((ip[8] as u128) << 56)
                + ((ip[9] as u128) << 48)
                + ((ip[10] as u128) << 40)
                + ((ip[11] as u128) << 32)
                + ((ip[12] as u128) << 24)
                + ((ip[13] as u128) << 16)
                + ((ip[14] as u128) << 8)
                + (ip[15] as u128);
            let xor_ip128 = ip128 ^ MAGIC_COOKIE as u128;
            buf.put_slice(&[
                0x0 as u8,
                0x2 as u8,
                (xport >> 8) as u8,
                xport as u8,
                (xor_ip128 >> 120) as u8,
                (xor_ip128 >> 112) as u8,
                (xor_ip128 >> 104) as u8,
                (xor_ip128 >> 96) as u8,
                (xor_ip128 >> 88) as u8,
                (xor_ip128 >> 80) as u8,
                (xor_ip128 >> 72) as u8,
                (xor_ip128 >> 64) as u8,
                (xor_ip128 >> 56) as u8,
                (xor_ip128 >> 48) as u8,
                (xor_ip128 >> 40) as u8,
                (xor_ip128 >> 32) as u8,
                (xor_ip128 >> 24) as u8,
                (xor_ip128 >> 16) as u8,
                (xor_ip128 >> 8) as u8,
                xor_ip128 as u8,
            ]);
            buf.freeze()
        }
    }
}

fn decode_change_req(data: &[u8]) -> IResult<&[u8], u8> {
    bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
        tuple((take(24usize), take(8usize))),
        |(_, ip_port): (u32, u8)| ip_port >> 1,
    ))(data)
}

fn encode_change_req(ip_port: &u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_slice(&[0 as u8, 0 as u8, 0 as u8, (ip_port << 1) as u8]);
    buf.freeze()
}

fn decode_attr_err(data: &[u8]) -> IResult<&[u8], (u16, String)> {
    bits::<_, _, Error<(&[u8], usize)>, _, _>(map(
        tuple((take(20usize), take(4usize), take(8usize))),
        |(_, cls, num): (u32, u16, u16)| {
            let class = cls & 15;
            let s = match str::from_utf8(&data[4..]) {
                Ok(v) => v,
                Err(_) => "Invalid UTF-8 sequence",
            };
            (class * 100 + num, s.to_string())
        },
    ))(data)
}

fn encode_attr_err(code: &u16, reason: &String) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    let divisor: u16 = 100;
    let class: u16 = code / divisor;
    let number: u8 = (code % divisor) as u8;
    buf.put_slice(&[0 as u8, (class >> 8) as u8, class as u8, number]);
    buf.put(reason.as_bytes());
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::StunAttribute;
    use crate::stun_type::{StunAttrType, StunAttrValue};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn extract_attrs_succeeds() {
        let bytes: &[u8] = &[
            0x00, 0x16, 0x00, 0x08, 0x00, 0x01, 0x4A, 0x86, 0x6B, 0x6F, 0x28, 0x17, 0x00, 0x20,
            0x00, 0x08, 0x00, 0x01, 0x3B, 0x13, 0x9D, 0x0F, 0x00, 0xBF, 0x00, 0x0D, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x14, 0xD2, 0x27, 0xB9, 0x81, 0xCE, 0x02,
            0xE6, 0x26, 0xF6, 0x79, 0xFA, 0xB3, 0x87, 0xC4, 0x99, 0x41, 0xE5, 0x11, 0x7F, 0x80,
        ];
        let (_, res) = super::from_bytes(bytes, bytes.len() as u16).unwrap();
        let res_bytes = super::to_bytes(&res);
        let bytes2: &[u8] = &[
            0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x22, 0x43, 0x4E,
            0x54, 0x6F, 0x33, 0x4F, 0x6B, 0x46, 0x45, 0x67, 0x61, 0x6D, 0x56, 0x78, 0x47, 0x33,
            0x66, 0x39, 0x41, 0x59, 0x71, 0x76, 0x47, 0x67, 0x67, 0x71, 0x4D, 0x4B, 0x49, 0x49,
            0x43, 0x6A, 0x42, 0x51, 0x00, 0x00, 0x00, 0x14, 0x00, 0x11, 0x73, 0x74, 0x75, 0x6E,
            0x2E, 0x6C, 0x2E, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00,
            0x00, 0x00, 0x00, 0x15, 0x00, 0x10, 0x06, 0x76, 0x07, 0x35, 0x80, 0x59, 0xAD, 0xA3,
            0x10, 0x01, 0x34, 0xA0, 0xE7, 0x33, 0x09, 0x6D, 0x00, 0x08, 0x00, 0x14, 0x52, 0x5A,
            0x1D, 0xD9, 0xD7, 0xE7, 0xA0, 0xD0, 0xA6, 0x12, 0xF2, 0x31, 0xC3, 0x75, 0xD1, 0x6F,
            0xA2, 0x81, 0x72, 0xA2, 0x00, 0x09, 0x00, 0x15, 0x00, 0x00, 0x00, 0x05, 0x53, 0x6F,
            0x6D, 0x65, 0x20, 0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D, 0x20, 0x65, 0x72, 0x72, 0x6F,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
        ];
        let (_, res2) = super::from_bytes(bytes2, bytes2.len() as u16).unwrap();
        let res2_bytes = super::to_bytes(&res2);
        assert_eq!(bytes[..], res_bytes[..]);
        assert_eq!(bytes2[..], res2_bytes[..]);
        assert_eq!(
            res,
            vec![
                StunAttribute {
                    format: StunAttrType::XorRelayedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(74, 125, 140, 85)), 27540)
                },
                StunAttribute {
                    format: StunAttrType::XorMappedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(188, 29, 164, 253)), 6657)
                },
                StunAttribute {
                    format: StunAttrType::Lifetime,
                    value: StunAttrValue::Value([0, 0, 0, 120].to_vec())
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(
                        [
                            210, 39, 185, 129, 206, 2, 230, 38, 246, 121, 250, 179, 135, 196, 153,
                            65, 229, 17, 127, 128
                        ]
                        .to_vec()
                    )
                }
            ]
        );
        assert_eq!(
            res2,
            vec![
                StunAttribute {
                    format: StunAttrType::RequestedTransport,
                    value: StunAttrValue::Value([17, 0, 0, 0].to_vec())
                },
                StunAttribute {
                    format: StunAttrType::Username,
                    value: StunAttrValue::Value(
                        [
                            67, 78, 84, 111, 51, 79, 107, 70, 69, 103, 97, 109, 86, 120, 71, 51,
                            102, 57, 65, 89, 113, 118, 71, 103, 103, 113, 77, 75, 73, 73, 67, 106,
                            66, 81
                        ]
                        .to_vec()
                    )
                },
                StunAttribute {
                    format: StunAttrType::Realm,
                    value: StunAttrValue::Value(
                        [
                            115, 116, 117, 110, 46, 108, 46, 103, 111, 111, 103, 108, 101, 46, 99,
                            111, 109
                        ]
                        .to_vec()
                    )
                },
                StunAttribute {
                    format: StunAttrType::Nonce,
                    value: StunAttrValue::Value(
                        [6, 118, 7, 53, 128, 89, 173, 163, 16, 1, 52, 160, 231, 51, 9, 109]
                            .to_vec()
                    )
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(
                        [
                            82, 90, 29, 217, 215, 231, 160, 208, 166, 18, 242, 49, 195, 117, 209,
                            111, 162, 129, 114, 162
                        ]
                        .to_vec()
                    )
                },
                StunAttribute {
                    format: StunAttrType::ErrorCode,
                    value: StunAttrValue::ErrorAttr(5, "Some random error".to_string())
                },
                StunAttribute {
                    format: StunAttrType::ChangeRequest,
                    value: StunAttrValue::Request(1 << 2 as u8)
                }
            ]
        );
    }
}
