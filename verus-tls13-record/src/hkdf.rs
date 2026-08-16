use crate::Error;

pub const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";

/// Borrowed, allocation-free encoding of RFC 8446 HkdfLabel. The provider
/// consumes `parts()` as if the slices were concatenated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HkdfLabel<'a> {
    output_len: [u8; 2],
    label_len: [u8; 1],
    label: &'a [u8],
    context_len: [u8; 1],
    context: &'a [u8],
}

impl<'a> HkdfLabel<'a> {
    pub fn new(output_len: usize, label: &'a [u8], context: &'a [u8]) -> Result<Self, Error> {
        if output_len > u16::MAX as usize
            || label.len() > u8::MAX as usize - TLS13_LABEL_PREFIX.len()
            || context.len() > u8::MAX as usize
        {
            return Err(Error::IllegalParameter);
        }
        Ok(Self {
            output_len: (output_len as u16).to_be_bytes(),
            label_len: [(TLS13_LABEL_PREFIX.len() + label.len()) as u8],
            label,
            context_len: [context.len() as u8],
            context,
        })
    }

    pub fn parts(&self) -> [&[u8]; 6] {
        [
            &self.output_len,
            &self.label_len,
            TLS13_LABEL_PREFIX,
            self.label,
            &self.context_len,
            self.context,
        ]
    }

    pub fn encoded_len(&self) -> usize {
        2 + 1 + TLS13_LABEL_PREFIX.len() + self.label.len() + 1 + self.context.len()
    }
}

pub fn key_label(key_len: usize) -> Result<HkdfLabel<'static>, Error> {
    HkdfLabel::new(key_len, b"key", b"")
}

pub fn iv_label() -> Result<HkdfLabel<'static>, Error> {
    HkdfLabel::new(12, b"iv", b"")
}

pub fn traffic_update_label(hash_len: usize) -> Result<HkdfLabel<'static>, Error> {
    HkdfLabel::new(hash_len, b"traffic upd", b"")
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn concatenate(label: HkdfLabel<'_>) -> Vec<u8> {
        label.parts().into_iter().flatten().copied().collect()
    }

    #[test]
    fn exact_key_iv_and_update_labels() {
        assert_eq!(
            concatenate(key_label(16).unwrap()),
            [0, 16, 9, b't', b'l', b's', b'1', b'3', b' ', b'k', b'e', b'y', 0]
        );
        assert_eq!(
            concatenate(iv_label().unwrap()),
            [0, 12, 8, b't', b'l', b's', b'1', b'3', b' ', b'i', b'v', 0]
        );
        assert_eq!(
            concatenate(traffic_update_label(32).unwrap()),
            [
                0, 32, 17, b't', b'l', b's', b'1', b'3', b' ', b't', b'r', b'a', b'f',
                b'f', b'i', b'c', b' ', b'u', b'p', b'd', 0,
            ]
        );
    }

    #[test]
    fn rejects_unencodable_lengths() {
        assert_eq!(
            HkdfLabel::new(usize::MAX, b"key", b"").unwrap_err(),
            Error::IllegalParameter
        );
        assert_eq!(
            HkdfLabel::new(16, &[0; 250], b"").unwrap_err(),
            Error::IllegalParameter
        );
    }
}
