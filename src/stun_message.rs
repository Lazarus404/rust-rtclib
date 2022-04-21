use crate::stun_attribute::{
    from_bytes as attr_from_bytes, to_bytes as attr_to_bytes, StunAttribute,
};
use crate::stun_error::StunError;
use crate::stun_header::{from_bytes as header_from_bytes, StunHeader};
use crate::stun_type::{StunAttrType, StunAttrValue};
use bytes::{BufMut, Bytes, BytesMut};
use hmacsha1::hmac_sha1;
use std::{str, str::Utf8Error};

#[derive(PartialEq, Debug)]
pub struct StunMessage {
    header: StunHeader,
    attributes: Vec<StunAttribute>,
    fingerprint: bool,
    integrity: bool,
}

pub fn from_bytes(input: &[u8]) -> Result<(&[u8], StunMessage), StunError> {
    let (rem_hdr, header) = header_from_bytes(input)?;
    let (rem_attr, attributes) = attr_from_bytes(&rem_hdr[..], header.length)?;
    let fingerprint = attributes
        .iter()
        .any(|attr| attr.format == StunAttrType::Fingerprint);
    let integrity = attributes
        .iter()
        .any(|attr| attr.format == StunAttrType::MessageIntegrity);
    Ok((
        &rem_attr[..],
        StunMessage {
            header,
            attributes,
            fingerprint,
            integrity,
        },
    ))
}

impl StunMessage {
    pub fn to_bytes(&self, key: &[u8]) -> Bytes {
        let mut attrs = self.attributes.to_vec();
        for indx in (0..attrs.len()).rev() {
            if attrs[indx].format == StunAttrType::MessageIntegrity
                || attrs[indx].format == StunAttrType::Fingerprint
            {
                attrs.swap_remove(indx);
            }
        }
        let attr_bytes = attr_to_bytes(&attrs);
        let mut len = attr_bytes.len() as u16;
        if self.integrity && key.len() > 0 {
            len += 24;
        };
        let header_bytes = StunHeader {
            class: self.header.class,
            method: self.header.method,
            length: len,
            transaction_id: self.header.transaction_id,
        }
        .to_bytes();
        let len_with_hdr = header_bytes.len() + len as usize;
        let mut buf = BytesMut::with_capacity(len_with_hdr);
        buf.put_slice(&header_bytes[..]);
        buf.put_slice(&attr_bytes[..]);
        if self.integrity && key.len() > 0 {
            let integrity = hmac_sha1(&key[..], &buf[..]);
            buf.put_slice(&[0x00, 0x08, 0x00, 0x14][..]);
            buf.put_slice(&integrity[..]);
        };
        if self.fingerprint {
            let buf_len = &mut buf[2..4];
            buf_len.copy_from_slice(&((len + 8) as u16).to_be_bytes());
            let fp_hash =
                crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&buf[..]) ^ 0x5354554E;
            buf.resize(len_with_hdr + 8, 0u8);
            let buf_hd_len = &mut buf[len_with_hdr..][..4];
            buf_hd_len.copy_from_slice(&[0x80, 0x28, 0x00, 0x04][..]);
            let buf_tl_len = &mut buf[len_with_hdr + 4..][..4];
            buf_tl_len.copy_from_slice(&fp_hash.to_be_bytes());
        };
        buf.freeze()
    }

    pub fn check_integrity(input: &[u8], key: &[u8]) -> bool {
        if input.len() < 44 {
            return true;
        }
        let mut len: usize = (&input.len() - 44) as usize;
        if &input[input.len() - 8..][..4] == &[0x80, 0x28, 0x00, 0x04][..] {
            len -= 8
        }
        match &input[len..][..4] {
            &[0x00, 0x08, 0x00, 0x14] => {
                let data = &input[len + 4..][..20];
                let mut buf = BytesMut::with_capacity(len);
                buf.put_slice(&input[..2]);
                buf.put_u16((len + 44) as u16);
                buf.put_slice(&input[4..len]);
                let integrity = hmac_sha1(&key[..], &buf[..]);
                &data[..] == &integrity[..]
            }
            _ => true,
        }
    }

    pub fn get_attr(&self, attr_type: StunAttrType) -> Option<StunAttrValue> {
        let attrs = self.attributes.to_vec();
        for indx in (0..attrs.len()).rev() {
            if attrs[indx].format == attr_type {
                return Some(attrs[indx].value.clone());
            }
        }
        return None;
    }

    pub fn make_key<'a>(
        username: &'a [u8],
        realm: &'a [u8],
        password: &'a [u8],
    ) -> Result<md5::Digest, Utf8Error> {
        Ok(md5::compute(
            format!(
                "{}:{}:{}",
                str::from_utf8(username)?,
                str::from_utf8(realm)?,
                str::from_utf8(password)?
            )
            .as_bytes(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::StunMessage;
    use crate::stun_attribute::StunAttribute;
    use crate::stun_header::StunHeader;
    use crate::stun_type::{StunAttrType, StunAttrValue, StunClass, StunMethod};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn stun_bind_req_bin() -> [u8; 36] {
        [
            0, 1, 0, 16, 33, 18, 164, 66, 147, 49, 141, 31, 86, 17, 126, 65, 130, 38, 1, 0, 128,
            34, 0, 12, 112, 106, 110, 97, 116, 104, 45, 49, 46, 52, 0, 0,
        ]
    }
    fn stun_bind_req() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Request,
                method: StunMethod::Binding,
                length: 16,
                transaction_id: 45554200240623869818762035456,
            },
            attributes: vec![StunAttribute {
                format: StunAttrType::Software,
                value: StunAttrValue::Value(vec![
                    112, 106, 110, 97, 116, 104, 45, 49, 46, 52, 0, 0,
                ]),
            }],
            fingerprint: false,
            integrity: false,
        }
    }
    fn stun_bind_resp_bin() -> [u8; 88] {
        [
            1, 1, 0, 68, 33, 18, 164, 66, 147, 49, 141, 31, 86, 17, 126, 65, 130, 38, 1, 0, 0, 1,
            0, 8, 0, 1, 224, 252, 88, 198, 53, 113, 0, 4, 0, 8, 0, 1, 13, 150, 208, 109, 222, 137,
            0, 5, 0, 8, 0, 1, 13, 151, 208, 109, 222, 148, 128, 32, 0, 8, 0, 1, 193, 238, 121, 212,
            145, 51, 128, 34, 0, 16, 86, 111, 118, 105, 100, 97, 46, 111, 114, 103, 32, 48, 46, 57,
            54, 0,
        ]
    }
    fn stun_bind_resp() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Success,
                method: StunMethod::Binding,
                length: 68,
                transaction_id: 45554200240623869818762035456,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::MappedAddress,
                    value: StunAttrValue::Attr(IpAddr::V4(Ipv4Addr::new(88, 198, 53, 113)), 57596),
                },
                StunAttribute {
                    format: StunAttrType::SourceAddress,
                    value: StunAttrValue::Attr(IpAddr::V4(Ipv4Addr::new(208, 109, 222, 137)), 3478),
                },
                StunAttribute {
                    format: StunAttrType::ChangedAddress,
                    value: StunAttrValue::Attr(IpAddr::V4(Ipv4Addr::new(208, 109, 222, 148)), 3479),
                },
                StunAttribute {
                    format: StunAttrType::XVovidaXorMappedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(88, 198, 53, 113)), 57596),
                },
                StunAttribute {
                    format: StunAttrType::Software,
                    value: StunAttrValue::Value(vec![
                        86, 111, 118, 105, 100, 97, 46, 111, 114, 103, 32, 48, 46, 57, 54, 0,
                    ]),
                },
            ],
            fingerprint: false,
            integrity: false,
        }
    }

    #[test]
    fn simple_decoding_of_stun_binding_request() {
        let (_, stun) = super::from_bytes(&stun_bind_req_bin()[..]).unwrap();
        assert_eq!(stun_bind_req(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_binding_request() {
        assert_eq!(stun_bind_req_bin(), &stun_bind_req().to_bytes(&[][..])[..]);
    }

    #[test]
    fn simple_decoding_of_stun_binding_response() {
        let (_, stun) = super::from_bytes(&stun_bind_resp_bin()[..]).unwrap();
        assert_eq!(stun_bind_resp(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_binding_response() {
        assert_eq!(
            stun_bind_resp_bin(),
            &stun_bind_resp().to_bytes(&[][..])[..]
        );
    }

    fn password<'a>() -> &'a [u8; 22] {
        b"VOkJxbRl1RmTxUk/WvJxBt"
    }

    fn req_bin() -> [u8; 108] {
        [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4E,
            0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x00, 0x24,
            0x00, 0x04, 0x6E, 0x00, 0x01, 0xFF, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2F, 0xF9, 0xB1,
            0x51, 0x26, 0x3B, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6A, 0x3A, 0x68,
            0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9A, 0xEA, 0xA7, 0x0C,
            0xBF, 0xD8, 0xCB, 0x56, 0x78, 0x1E, 0xF2, 0xB5, 0xB2, 0xD3, 0xF2, 0x49, 0xC1, 0xB5,
            0x71, 0xA2, 0x80, 0x28, 0x00, 0x04, 0xE5, 0x7A, 0x3B, 0xCF,
        ]
    }

    fn req_bin_fixed() -> [u8; 108] {
        [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4E,
            0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x00, 0x24,
            0x00, 0x04, 0x6E, 0x00, 0x01, 0xFF, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2F, 0xF9, 0xB1,
            0x51, 0x26, 0x3B, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6A, 0x3A, 0x68,
            0x36, 0x76, 0x59, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x14, 0x79, 0x07, 0xC2, 0xD2,
            0xED, 0xBF, 0xEA, 0x48, 0x0E, 0x4C, 0x76, 0xD8, 0x29, 0x62, 0xD5, 0xC3, 0x74, 0x2A,
            0xF9, 0xE3, 0x80, 0x28, 0x00, 0x04, 0xE3, 0x52, 0x92, 0x8D,
        ]
    }

    fn req() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Request,
                method: StunMethod::Binding,
                length: 88,
                transaction_id: 56915807328848210473588875182,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::Software,
                    value: StunAttrValue::Value((b"STUN test client").to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::Priority,
                    value: StunAttrValue::Value([110, 0, 1, 255].to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::IceControlled,
                    value: StunAttrValue::Value([147, 47, 249, 177, 81, 38, 59, 54].to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::Username,
                    value: StunAttrValue::Value((b"evtj:h6vY").to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(
                        [
                            154, 234, 167, 12, 191, 216, 203, 86, 120, 30, 242, 181, 178, 211, 242,
                            73, 193, 181, 113, 162,
                        ]
                        .to_vec(),
                    ),
                },
                StunAttribute {
                    format: StunAttrType::Fingerprint,
                    value: StunAttrValue::Value([229, 122, 59, 207].to_vec()),
                },
            ],
            fingerprint: true,
            integrity: true,
        }
    }

    fn resp_ipv4_bin() -> [u8; 80] {
        [
            0x01, 0x01, 0x00, 0x3C, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x0B, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2B, 0x91, 0xF5, 0x99,
            0xFD, 0x9E, 0x90, 0xC3, 0x8C, 0x74, 0x89, 0xF9, 0x2A, 0xF9, 0xBA, 0x53, 0xF0, 0x6B,
            0xE7, 0xD7, 0x80, 0x28, 0x00, 0x04, 0xC0, 0x7D, 0x4C, 0x96,
        ]
    }

    fn resp_ipv4_bin_fixed() -> [u8; 80] {
        [
            0x01, 0x01, 0x00, 0x3C, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x0B, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x5D, 0x6B, 0x58, 0xBE,
            0xAD, 0x94, 0xE0, 0x7E, 0xEF, 0x0D, 0xFC, 0x12, 0x82, 0xA2, 0xBD, 0x08, 0x43, 0x14,
            0x10, 0x28, 0x80, 0x28, 0x00, 0x04, 0x25, 0x16, 0x7A, 0x15,
        ]
    }

    fn resp_ipv4() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Success,
                method: StunMethod::Binding,
                length: 60,
                transaction_id: 56915807328848210473588875182,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::Software,
                    value: StunAttrValue::Value(vec![
                        116, 101, 115, 116, 32, 118, 101, 99, 116, 111, 114,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::XorMappedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(vec![
                        43, 145, 245, 153, 253, 158, 144, 195, 140, 116, 137, 249, 42, 249, 186,
                        83, 240, 107, 231, 215,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::Fingerprint,
                    value: StunAttrValue::Value(vec![192, 125, 76, 150]),
                },
            ],
            fingerprint: true,
            integrity: true,
        }
    }

    fn resp_ipv6_bin() -> [u8; 92] {
        [
            0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x0B, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
            0xA1, 0x47, 0x01, 0x13, 0xA9, 0xFA, 0xA5, 0xD3, 0xF1, 0x79, 0xBC, 0x25, 0xF4, 0xB5,
            0xBE, 0xD2, 0xB9, 0xD9, 0x00, 0x08, 0x00, 0x14, 0xA3, 0x82, 0x95, 0x4E, 0x4B, 0xE6,
            0x7B, 0xF1, 0x17, 0x84, 0xC9, 0x7C, 0x82, 0x92, 0xC2, 0x75, 0xBF, 0xE3, 0xED, 0x41,
            0x80, 0x28, 0x00, 0x04, 0xC8, 0xFB, 0x0B, 0x4C,
        ]
    }

    fn resp_ipv6_bin_fixed() -> [u8; 92] {
        [
            0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xA4, 0x42, 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
            0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, 0x80, 0x22, 0x00, 0x0B, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x00, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
            0xA1, 0x47, 0x01, 0x13, 0xA9, 0xFA, 0xA5, 0xD3, 0xF1, 0x79, 0xBC, 0x25, 0xF4, 0xB5,
            0xBE, 0xD2, 0xB9, 0xD9, 0x00, 0x08, 0x00, 0x14, 0xBD, 0x03, 0x6D, 0x6A, 0x33, 0x17,
            0x50, 0xDF, 0xE2, 0xED, 0xC5, 0x8E, 0x64, 0x34, 0x55, 0xCF, 0xF5, 0xC8, 0xE2, 0x64,
            0x80, 0x28, 0x00, 0x04, 0x4F, 0x26, 0x02, 0x93,
        ]
    }

    fn resp_ipv6() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Success,
                method: StunMethod::Binding,
                length: 72,
                transaction_id: 56915807328848210473588875182,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::Software,
                    value: StunAttrValue::Value(vec![
                        116, 101, 115, 116, 32, 118, 101, 99, 116, 111, 114,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::XorMappedAddress,
                    value: StunAttrValue::XAttr(
                        "113:a9fa:a5d3:f179:bc25:f4b5:9fc0:1d9b".parse().unwrap(),
                        32853,
                    ),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(vec![
                        163, 130, 149, 78, 75, 230, 123, 241, 23, 132, 201, 124, 130, 146, 194,
                        117, 191, 227, 237, 65,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::Fingerprint,
                    value: StunAttrValue::Value(vec![200, 251, 11, 76]),
                },
            ],
            fingerprint: true,
            integrity: true,
        }
    }

    // "<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>"
    fn username() -> [u8; 18] {
        [
            227, 131, 158, 227, 131, 136, 227, 131, 170, 227, 131, 131, 227, 130, 175, 227, 130,
            185,
        ]
    }
    // @password = "The<U+00AD>M<U+00AA>tr<U+2168>",
    fn password_after_sasl_prep<'a>() -> &'a [u8; 9] {
        b"TheMatrIX"
    }
    fn realm<'a>() -> &'a [u8; 11] {
        b"example.org"
    }

    fn key() -> md5::Digest {
        StunMessage::make_key(
            &username()[..],
            &realm()[..],
            &password_after_sasl_prep()[..],
        )
        .unwrap()
    }

    fn req_auth_bin() -> [u8; 116] {
        [
            0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xA4, 0x42, 0x78, 0xAD, 0x34, 0x33, 0xC6, 0xAD,
            0x72, 0xC0, 0x29, 0xDA, 0x41, 0x2E, 0x00, 0x15, 0x00, 0x1C, 0x66, 0x2F, 0x2F, 0x34,
            0x39, 0x39, 0x6B, 0x39, 0x35, 0x34, 0x64, 0x36, 0x4F, 0x4C, 0x33, 0x34, 0x6F, 0x4C,
            0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x14, 0x00, 0x0B,
            0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x6F, 0x72, 0x67, 0x00, 0x00, 0x06,
            0x00, 0x12, 0xE3, 0x83, 0x9E, 0xE3, 0x83, 0x88, 0xE3, 0x83, 0xAA, 0xE3, 0x83, 0x83,
            0xE3, 0x82, 0xAF, 0xE3, 0x82, 0xB9, 0x00, 0x00, 0x00, 0x08, 0x00, 0x14, 0x3D, 0x64,
            0x0E, 0xB8, 0x0B, 0xB3, 0x4B, 0xA0, 0x38, 0x54, 0x60, 0x94, 0x1D, 0x3B, 0xCA, 0xC4,
            0xF6, 0x90, 0x45, 0x3B,
        ]
    }

    fn req_auth() -> StunMessage {
        StunMessage {
            header: StunHeader {
                class: StunClass::Request,
                method: StunMethod::Binding,
                length: 96,
                transaction_id: 37347591863512021035078271278,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::Nonce,
                    value: StunAttrValue::Value(vec![
                        102, 47, 47, 52, 57, 57, 107, 57, 53, 52, 100, 54, 79, 76, 51, 52, 111, 76,
                        57, 70, 83, 84, 118, 121, 54, 52, 115, 65,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::Realm,
                    value: StunAttrValue::Value(vec![
                        101, 120, 97, 109, 112, 108, 101, 46, 111, 114, 103,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::Username,
                    value: StunAttrValue::Value(vec![
                        227, 131, 158, 227, 131, 136, 227, 131, 170, 227, 131, 131, 227, 130, 175,
                        227, 130, 185,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(vec![
                        61, 100, 14, 184, 11, 179, 75, 160, 56, 84, 96, 148, 29, 59, 202, 196, 246,
                        144, 69, 59,
                    ]),
                },
            ],
            fingerprint: false,
            integrity: true,
        }
    }

    #[test]
    fn simple_decoding_of_stun_request() {
        let (_, stun) = super::from_bytes(&req_bin()[..]).unwrap();
        assert_eq!(req(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_request() {
        let bytes = &req().to_bytes(password())[..];
        assert!(StunMessage::check_integrity(&bytes[..], password()));
        assert_eq!(req_bin_fixed(), bytes);
    }

    #[test]
    fn simple_decoding_of_stun_ipv4_response() {
        let (_, stun) = super::from_bytes(&resp_ipv4_bin()[..]).unwrap();
        assert_eq!(resp_ipv4(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_ipv4_response() {
        let bytes = &resp_ipv4().to_bytes(password())[..];
        assert!(StunMessage::check_integrity(&bytes[..], password()));
        assert_eq!(resp_ipv4_bin_fixed(), bytes);
    }

    #[test]
    fn simple_decoding_of_stun_ipv6_response() {
        let (_, stun) = super::from_bytes(&resp_ipv6_bin()[..]).unwrap();
        assert_eq!(resp_ipv6(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_ipv6_response() {
        let bytes = &resp_ipv6().to_bytes(password())[..];
        assert!(StunMessage::check_integrity(&bytes[..], password()));
        assert_eq!(resp_ipv6_bin_fixed(), bytes);
    }

    #[test]
    fn simple_decoding_of_stun_request_with_auth() {
        let (_, stun) = super::from_bytes(&req_auth_bin()[..]).unwrap();
        assert_eq!(req_auth(), stun);
    }

    #[test]
    fn simple_encoding_of_stun_request_with_auth() {
        let bytes = &req_auth().to_bytes(&key()[..])[..];
        assert!(StunMessage::check_integrity(&bytes[..], &key()[..]));
        assert_eq!(req_auth_bin(), bytes);
    }

    fn google_request() -> [u8; 136] {
        [
            0x00, 0x03, 0x00, 0x74, 0x21, 0x12, 0xA4, 0x42, 0x73, 0x79, 0x33, 0x73, 0x68, 0x5A,
            0x4B, 0x7A, 0x4E, 0x64, 0x4E, 0x55, 0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x22, 0x43, 0x4E, 0x54, 0x6F, 0x33, 0x4F, 0x6B, 0x46, 0x45, 0x67,
            0x61, 0x6D, 0x56, 0x78, 0x47, 0x33, 0x66, 0x39, 0x41, 0x59, 0x71, 0x76, 0x47, 0x67,
            0x67, 0x71, 0x4D, 0x4B, 0x49, 0x49, 0x43, 0x6A, 0x42, 0x51, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x11, 0x73, 0x74, 0x75, 0x6E, 0x2E, 0x6C, 0x2E, 0x67, 0x6F, 0x6F, 0x67, 0x6C,
            0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x10, 0x06, 0x76,
            0x07, 0x35, 0x80, 0x59, 0xAD, 0xA3, 0x10, 0x01, 0x34, 0xA0, 0xE7, 0x33, 0x09, 0x6D,
            0x00, 0x08, 0x00, 0x14, 0x52, 0x5A, 0x1D, 0xD9, 0xD7, 0xE7, 0xA0, 0xD0, 0xA6, 0x12,
            0xF2, 0x31, 0xC3, 0x75, 0xD1, 0x6F, 0xA2, 0x81, 0x72, 0xA2,
        ]
    }

    fn google_response() -> [u8; 76] {
        [
            0x01, 0x03, 0x00, 0x38, 0x21, 0x12, 0xA4, 0x42, 0x73, 0x79, 0x33, 0x73, 0x68, 0x5A,
            0x4B, 0x7A, 0x4E, 0x64, 0x4E, 0x55, 0x00, 0x16, 0x00, 0x08, 0x00, 0x01, 0x4A, 0x86,
            0x6B, 0x6F, 0x28, 0x17, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x3B, 0x13, 0x9D, 0x0F,
            0x00, 0xBF, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x14,
            0xD2, 0x27, 0xB9, 0x81, 0xCE, 0x02, 0xE6, 0x26, 0xF6, 0x79, 0xFA, 0xB3, 0x87, 0xC4,
            0x99, 0x41, 0xE5, 0x11, 0x7F, 0x80,
        ]
    }

    #[test]
    fn google_request_success() {
        let msg: StunMessage = StunMessage {
            header: StunHeader {
                class: StunClass::Request,
                method: StunMethod::Allocate,
                length: 116,
                transaction_id: 35737299123213653378515357269,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::RequestedTransport,
                    value: StunAttrValue::Value(vec![17, 0, 0, 0]),
                },
                StunAttribute {
                    format: StunAttrType::Username,
                    value: StunAttrValue::Value(b"CNTo3OkFEgamVxG3f9AYqvGggqMKIICjBQ".to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::Realm,
                    value: StunAttrValue::Value(b"stun.l.google.com".to_vec()),
                },
                StunAttribute {
                    format: StunAttrType::Nonce,
                    value: StunAttrValue::Value(vec![
                        6, 118, 7, 53, 128, 89, 173, 163, 16, 1, 52, 160, 231, 51, 9, 109,
                    ]),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(vec![
                        82, 90, 29, 217, 215, 231, 160, 208, 166, 18, 242, 49, 195, 117, 209, 111,
                        162, 129, 114, 162,
                    ]),
                },
            ],
            fingerprint: false,
            integrity: true,
        };
        let (_, stun) = super::from_bytes(&google_request()[..]).unwrap();
        assert_eq!(msg, stun);
    }

    #[test]
    fn google_response_success() {
        let msg: StunMessage = StunMessage {
            header: StunHeader {
                class: StunClass::Success,
                method: StunMethod::Allocate,
                length: 56,
                transaction_id: 35737299123213653378515357269,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::XorRelayedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(74, 125, 140, 85)), 27540),
                },
                StunAttribute {
                    format: StunAttrType::XorMappedAddress,
                    value: StunAttrValue::XAttr(IpAddr::V4(Ipv4Addr::new(188, 29, 164, 253)), 6657),
                },
                StunAttribute {
                    format: StunAttrType::Lifetime,
                    value: StunAttrValue::Value(vec![0, 0, 0, 120]),
                },
                StunAttribute {
                    format: StunAttrType::MessageIntegrity,
                    value: StunAttrValue::Value(vec![
                        210, 39, 185, 129, 206, 2, 230, 38, 246, 121, 250, 179, 135, 196, 153, 65,
                        229, 17, 127, 128,
                    ]),
                },
            ],
            fingerprint: false,
            integrity: true,
        };
        let (_, stun) = super::from_bytes(&google_response()[..]).unwrap();
        assert_eq!(msg, stun);
    }

    fn xturn_response() -> [u8; 136] {
        [
            0x00, 0x16, 0x00, 0x74, 0x21, 0x12, 0xA4, 0x42, 0x74, 0x53, 0x74, 0x51, 0x78, 0x59,
            0x61, 0x54, 0x48, 0x4F, 0x59, 0x30, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0xC2, 0xA9,
            0x98, 0x9A, 0x4D, 0xE2, 0x00, 0x13, 0x00, 0x64, 0x00, 0x01, 0x00, 0x50, 0x21, 0x12,
            0xA4, 0x42, 0x6F, 0x48, 0x53, 0x47, 0x52, 0x41, 0x74, 0x4F, 0x52, 0x46, 0x55, 0x35,
            0x00, 0x06, 0x00, 0x09, 0x35, 0x37, 0x51, 0x4F, 0x3A, 0x73, 0x75, 0x35, 0x69, 0x00,
            0x00, 0x00, 0xC0, 0x57, 0x00, 0x04, 0x00, 0x01, 0x00, 0x0A, 0x80, 0x2A, 0x00, 0x08,
            0x5A, 0x0F, 0x8D, 0x6C, 0x97, 0x61, 0xCA, 0xBE, 0x00, 0x25, 0x00, 0x00, 0x00, 0x24,
            0x00, 0x04, 0x6E, 0x7F, 0x1E, 0xFF, 0x00, 0x08, 0x00, 0x14, 0x8F, 0x0D, 0xDA, 0x13,
            0xC4, 0x94, 0x01, 0x5D, 0xDB, 0x75, 0x7A, 0x27, 0x19, 0x4D, 0xDB, 0xAC, 0xB3, 0x82,
            0x4A, 0x3F, 0x80, 0x28, 0x00, 0x04, 0x7D, 0x86, 0xC8, 0x55,
        ]
    }

    #[test]
    fn xturn_response_success() {
        let msg: StunMessage = StunMessage {
            header: StunHeader {
                class: StunClass::Indication,
                method: StunMethod::SendIndication,
                length: 116,
                transaction_id: 36001151279674394614990592304,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::XorPeerAddress,
                    value: StunAttrValue::XAttr(
                        IpAddr::V4(Ipv4Addr::new(185, 136, 233, 160)),
                        58299,
                    ),
                },
                StunAttribute {
                    format: StunAttrType::Data,
                    value: StunAttrValue::Value(vec![
                        0, 1, 0, 80, 33, 18, 164, 66, 111, 72, 83, 71, 82, 65, 116, 79, 82, 70, 85,
                        53, 0, 6, 0, 9, 53, 55, 81, 79, 58, 115, 117, 53, 105, 0, 0, 0, 192, 87, 0,
                        4, 0, 1, 0, 10, 128, 42, 0, 8, 90, 15, 141, 108, 151, 97, 202, 190, 0, 37,
                        0, 0, 0, 36, 0, 4, 110, 127, 30, 255, 0, 8, 0, 20, 143, 13, 218, 19, 196,
                        148, 1, 93, 219, 117, 122, 39, 25, 77, 219, 172, 179, 130, 74, 63, 128, 40,
                        0, 4, 125, 134, 200, 85,
                    ]),
                },
            ],
            fingerprint: false,
            integrity: false,
        };
        let (_, stun) = super::from_bytes(&xturn_response()[..]).unwrap();
        assert_eq!(msg, stun);
    }

    #[test]
    fn decode_message_succeeds() {
        let bytes: &[u8] = &xturn_response()[..];
        let model = StunMessage {
            header: StunHeader {
                class: StunClass::Indication,
                method: StunMethod::SendIndication,
                length: 116,
                transaction_id: 36001151279674394614990592304,
            },
            attributes: vec![
                StunAttribute {
                    format: StunAttrType::XorPeerAddress,
                    value: StunAttrValue::XAttr(
                        IpAddr::V4(Ipv4Addr::new(185, 136, 233, 160)),
                        58299,
                    ),
                },
                StunAttribute {
                    format: StunAttrType::Data,
                    value: StunAttrValue::Value(
                        [
                            0, 1, 0, 80, 33, 18, 164, 66, 111, 72, 83, 71, 82, 65, 116, 79, 82, 70,
                            85, 53, 0, 6, 0, 9, 53, 55, 81, 79, 58, 115, 117, 53, 105, 0, 0, 0,
                            192, 87, 0, 4, 0, 1, 0, 10, 128, 42, 0, 8, 90, 15, 141, 108, 151, 97,
                            202, 190, 0, 37, 0, 0, 0, 36, 0, 4, 110, 127, 30, 255, 0, 8, 0, 20,
                            143, 13, 218, 19, 196, 148, 1, 93, 219, 117, 122, 39, 25, 77, 219, 172,
                            179, 130, 74, 63, 128, 40, 0, 4, 125, 134, 200, 85,
                        ]
                        .to_vec(),
                    ),
                },
            ],
            fingerprint: false,
            integrity: false,
        };
        let start = SystemTime::now();
        let (_, res) = super::from_bytes(bytes).unwrap();
        println!("TIME 1: {:?}", start.elapsed().unwrap());
        let res2 = model.to_bytes(&b""[..]);
        println!("TIME 2: {:?}", start.elapsed().unwrap());
        assert_eq!(res, model);
        assert_eq!(&res2[..], bytes);
    }

    #[test]
    fn decode_message_with_integrity_succeeds() {
        let bytes: &[u8] = &req_bin();
        let model = req();
        let start = SystemTime::now();
        let (_, res) = super::from_bytes(&bytes[..]).unwrap();
        println!("TIME 1b: {:?}", start.elapsed().unwrap());
        let res2 = res.to_bytes(&password()[..]);
        println!("TIME 2b: {:?}", start.elapsed().unwrap());
        assert_eq!(&res, &model);
        assert_eq!(&res2[..], &req_bin_fixed()[..]);
    }
}
