// use crate::stun_error::StunError;
// use crate::stun_header::StunHeader;
// use crate::stun_attribute::StunAttribute;
// use nom::IResult;
// use nom::Err;
// use nom::error::Error;

// pub struct StunMessage {
//     header: StunHeader,
//     attributes: StunAttribute
// }

// impl StunMessage {
//     pub fn from_bytes(input: &[u8]) -> Result<StunMessage, nom::Err<Error<&[u8]>>> {
//         let header = StunHeader::from_bytes(input);
//         match header {
//             Err(e) => return Err(e),
//             res => res
//         };
//         let attributes = StunAttribute::from_bytes(&input[20..]);
//         match attributes {
//             Err(e) => return Err(e),
//             res => res
//         };
//         Ok(StunMessage { header, attributes });
//     }
// }
