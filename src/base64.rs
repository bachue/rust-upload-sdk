pub(super) use base64::DecodeError;
use std::result::Result;

#[inline]
pub(super) fn urlsafe_encode(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE)
}

#[inline]
pub(super) fn urlsafe_encode_buf(data: &[u8], mut encoded: &mut String) {
    base64::encode_config_buf(data, base64::URL_SAFE, &mut encoded)
}

#[inline]
pub(super) fn urlsafe_encode_slice(data: &[u8], mut encoded: &mut [u8]) -> usize {
    base64::encode_config_slice(data, base64::URL_SAFE, &mut encoded)
}

#[inline]
pub(super) fn urlsafe_decode(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(data, base64::URL_SAFE)
}

#[inline]
pub(super) fn urlsafe_decode_buf(
    data: &[u8],
    mut decoded: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    base64::decode_config_buf(data, base64::URL_SAFE, &mut decoded)
}

#[inline]
pub(super) fn urlsafe_decode_slice(
    data: &[u8],
    mut decoded: &mut [u8],
) -> Result<usize, DecodeError> {
    base64::decode_config_slice(data, base64::URL_SAFE, &mut decoded)
}
