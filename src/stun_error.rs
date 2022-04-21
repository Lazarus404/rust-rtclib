#[derive(PartialEq, Debug)]
pub enum StunError {
    Incomplete(u16),
    Invalid,
    BadIntegrity,
    BadFingerprint,
}
