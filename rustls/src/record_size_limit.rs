use core::fmt;

/// A TLS 1.3 `record_size_limit` value from RFC 8449.
///
/// The value includes the inner content-type octet and any TLS 1.3 padding.
/// It is a receive capability: configuring it advertises the largest protected
/// `TLSInnerPlaintext` this endpoint accepts. `None` in a connection config
/// leaves the extension absent and retains the RFC 8446 maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSizeLimit(verus_tls13_record::Limit);

impl RecordSizeLimit {
    /// Construct a limit in the selected TLS 1.3 range `64..=16_385`.
    pub fn new(value: usize) -> Result<Self, InvalidRecordSizeLimit> {
        verus_tls13_record::Limit::new(value)
            .map(Self)
            .map_err(|_| InvalidRecordSizeLimit)
    }

    /// Return the encoded RFC 8449 value.
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    pub(crate) const fn into_inner(self) -> verus_tls13_record::Limit {
        self.0
    }
}

/// The requested record size was outside `64..=16_385`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRecordSizeLimit;

impl fmt::Display for InvalidRecordSizeLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("record size limit must be in 64..=16385")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidRecordSizeLimit {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_boundaries() {
        assert_eq!(RecordSizeLimit::new(63), Err(InvalidRecordSizeLimit));
        assert_eq!(RecordSizeLimit::new(64).unwrap().get(), 64);
        assert_eq!(RecordSizeLimit::new(16_385).unwrap().get(), 16_385);
        assert_eq!(RecordSizeLimit::new(16_386), Err(InvalidRecordSizeLimit));
    }
}
