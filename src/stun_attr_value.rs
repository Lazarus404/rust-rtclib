use std::net::IpAddr;

#[derive(PartialEq, Debug)]
pub enum StunAttrValue {
    Value(Vec<u8>),
    Attr(IpAddr, u16),
    XAttr(IpAddr, u16),
    ErrorAttr(u16, String),
    Request(u8),
}

enum_from_primitive! {
    #[derive(Debug, PartialEq)]
    pub enum StunChangeRequestType {
        Ip = 1,
        Port = 2,
    }
}

enum_from_primitive! {
    #[derive(Debug, PartialEq)]
    pub enum StunAttrType {
        MappedAddress = 1,
        ResponseAddress = 2,
        ChangeRequest = 3,
        SourceAddress = 4,
        ChangedAddress = 5,
        Username = 6,
        Password = 7,
        MessageIntegrity = 8,
        ErrorCode = 9,
        UnknownAttributes = 10,
        ReflectedFrom = 11,
        ChannelNumber = 12,
        Lifetime = 13,
        AlternateServer = 14,
        MagicCookie = 15,
        Bandwidth = 16,
        DestinationAddress = 17,
        XorPeerAddress = 18,
        Data = 19,
        Realm = 20,
        Nonce = 21,
        XorRelayedAddress = 22,
        RequestedAddressType = 23,
        EvenPort = 24,
        RequestedTransport = 25,
        DontFragment = 26,
        XorMappedAddress = 32,
        ReservationToken = 34,
        Priority = 36,
        UseCandidate = 37,
        Padding = 38,
        ResponsePort = 39,
        XorReflectedFrom = 40,
        ConnectionID = 42,
        Ping = 48,
        XVovidaXorMappedAddress = 32800,
        XVovidaXorOnly = 32801,
        Software = 32802,
        AltServer = 32803,
        CacheTimeout = 32807,
        Fingerprint = 32808,
        IceControlled = 32809,
        IceControlling = 32810,
        ResponseOrigin = 32811,
        OtherAddress = 32812,
        XVovidaSecondaryAddress = 32848,
        ConnectionRequestBinding = 49153,
        BindingChange = 49154,
    }
}
