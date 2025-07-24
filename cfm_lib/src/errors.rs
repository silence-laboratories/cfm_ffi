#[derive(Debug, thiserror::Error)]
/// PSC BB errors
pub enum PSCBBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,
}

#[derive(Debug, thiserror::Error)]
/// PSC OB errors
pub enum PSCOBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    #[error("Invalid DLog proof")]
    /// Invalid DLog proof
    InvalidDLogProof,
}

#[derive(Debug, thiserror::Error)]
/// PSIT CB errors
pub enum PSITCBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,
}

#[derive(Debug, thiserror::Error)]
/// PSIT OB errors
pub enum PSITOBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    #[error("Invalid DLog proof")]
    /// Invalid DLog proof
    InvalidDLogProof,

    #[error("Not in list")]
    /// Not in list
    NotInList,
}

#[derive(Debug, thiserror::Error)]
/// ABT CB errors
pub enum ABTCBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    /// invalid state
    #[error("invalid state")]
    InvalidState,

    /// invalid open
    #[error("Invalid Open")]
    InvalidOpen,

    /// Abort the protocol and ban other party
    #[error("Abort the protocol and ban other party")]
    AbortProtocolAndBanOtherParty,
}

#[derive(Debug, thiserror::Error)]
/// ABT OB errors
pub enum ABTOBError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    /// invalid state
    #[error("invalid state")]
    InvalidState,

    /// invalid commitment of rho1 value
    #[error("Invalid Commitment")]
    InvalidCommitment,

    /// invalid open
    #[error("Invalid Open")]
    InvalidOpen,

    /// Abort the protocol and ban other party
    #[error("Abort the protocol and ban other party")]
    AbortProtocolAndBanOtherParty,
}

#[derive(Debug, thiserror::Error)]
/// ABT CB errors
pub enum CompError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// invalid open
    #[error("Invalid Open")]
    InvalidOpen,
}

#[derive(Debug, thiserror::Error)]
/// PSIT CB errors
pub enum CFMError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    /// invalid open
    #[error("Invalid Open")]
    InvalidOpen,

    /// error in PSIT protocol
    #[error("PSIT Error")]
    PSITError,

    /// abort protocol
    #[error("Abort protocol")]
    AbortProtocol,

    /// Comparison error
    #[error("Comparison error")]
    Comparison,
}
