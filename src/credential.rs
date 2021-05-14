use crate::base64;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use std::{
    any::Any,
    borrow::Cow,
    convert::TryFrom,
    fmt::{self, Debug},
    io::{Error, Result},
};

/// 认证信息
///
/// 返回认证信息的 AccessKey 和 SecretKey
#[derive(Clone, Debug)]
pub(super) struct Credential<'a> {
    access_key: Cow<'a, str>,
    secret_key: Cow<'a, str>,
}

impl<'a> Credential<'a> {
    #[inline]
    pub(super) fn new(
        access_key: impl Into<Cow<'a, str>>,
        secret_key: impl Into<Cow<'a, str>>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }

    #[inline]
    pub(super) fn access_key(&self) -> &str {
        self.access_key.as_ref()
    }

    #[inline]
    pub(super) fn secret_key(&self) -> &str {
        self.secret_key.as_ref()
    }

    #[inline]
    pub(super) fn into_pair(self) -> (Cow<'a, str>, Cow<'a, str>) {
        (self.access_key, self.secret_key)
    }

    #[inline]
    pub(super) fn access_key_mut(&mut self) -> &mut Cow<'a, str> {
        &mut self.access_key
    }

    #[inline]
    pub(super) fn secret_key_mut(&mut self) -> &mut Cow<'a, str> {
        &mut self.secret_key
    }
}

impl Credential<'_> {
    pub(super) fn sign(&self, data: &[u8]) -> String {
        self.access_key.to_owned().into_owned()
            + ":"
            + &base64ed_hmac_digest(self.secret_key.as_ref(), data)
    }

    pub(super) fn sign_with_data(&self, data: &[u8]) -> String {
        let encoded_data = base64::urlsafe_encode(data);
        self.sign(encoded_data.as_bytes()) + ":" + &encoded_data
    }
}

fn base64ed_hmac_digest(secret_key: &str, data: &[u8]) -> String {
    let mut hmac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes()).unwrap();
    hmac.update(data);
    base64::urlsafe_encode(&hmac.finalize().into_bytes())
}

pub(super) trait CredentialProvider: Any + Debug + Sync + Send {
    fn get(&self) -> Result<Credential>;
    fn as_any(&self) -> &dyn Any;
    fn as_credential_provider(&self) -> &dyn CredentialProvider;
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct StaticCredentialProvider {
    access_key: Cow<'static, str>,
    secret_key: Cow<'static, str>,
}

impl StaticCredentialProvider {
    pub(super) fn new(
        access_key: impl Into<Cow<'static, str>>,
        secret_key: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }
}

impl CredentialProvider for StaticCredentialProvider {
    #[inline]
    fn get(&self) -> Result<Credential> {
        Ok(Credential::new(
            Cow::Borrowed(self.access_key.as_ref()),
            Cow::Borrowed(self.secret_key.as_ref()),
        ))
    }

    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn as_credential_provider(&self) -> &dyn CredentialProvider {
        self
    }
}

impl TryFrom<&dyn CredentialProvider> for StaticCredentialProvider {
    type Error = Error;
    fn try_from(cred: &dyn CredentialProvider) -> Result<Self> {
        let value = cred.get()?;
        Ok(StaticCredentialProvider::new(
            value.access_key.into_owned(),
            value.secret_key.into_owned(),
        ))
    }
}

impl AsRef<dyn CredentialProvider> for StaticCredentialProvider {
    #[inline]
    fn as_ref(&self) -> &dyn CredentialProvider {
        self.as_credential_provider()
    }
}

impl Debug for StaticCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "StaticCredentialProvider {{ access_key: {:?}, secret_key: CENSORED }}",
            self.access_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{boxed::Box, error::Error, result::Result, sync::Arc, thread};

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let credential: Arc<dyn CredentialProvider> = Arc::new(get_static_credential());
        let mut threads = Vec::new();
        {
            let credential = credential.clone();
            threads.push(thread::spawn(move || {
                assert_eq!(
                    credential.get().unwrap().sign(b"hello"),
                    "abcdefghklmnopq:b84KVc-LroDiz0ebUANfdzSRxa0="
                );
                assert_eq!(
                    credential.get().unwrap().sign(b"world"),
                    "abcdefghklmnopq:VjgXt0P_nCxHuaTfiFz-UjDJ1AQ="
                );
            }));
        }
        {
            let credential = credential.clone();
            threads.push(thread::spawn(move || {
                assert_eq!(
                    credential.get().unwrap().sign(b"-test"),
                    "abcdefghklmnopq:vYKRLUoXRlNHfpMEQeewG0zylaw="
                );
                assert_eq!(
                    credential.get().unwrap().sign(b"ba#a-"),
                    "abcdefghklmnopq:2d_Yr6H1GdTKg3RvMtpHOhi047M="
                );
            }));
        }
        threads
            .into_iter()
            .for_each(|thread| thread.join().unwrap());
        Ok(())
    }

    #[test]
    fn test_sign_data() -> Result<(), Box<dyn Error>> {
        let credential: Arc<dyn CredentialProvider> = Arc::new(get_static_credential());
        let mut threads = Vec::new();
        {
            let credential = credential.clone();
            threads.push(thread::spawn(move || {
                assert_eq!(
                    credential.get().unwrap().sign_with_data(b"hello"),
                    "abcdefghklmnopq:BZYt5uVRy1RVt5ZTXbaIt2ROVMA=:aGVsbG8="
                );
                assert_eq!(
                    credential.get().unwrap().sign_with_data(b"world"),
                    "abcdefghklmnopq:Wpe04qzPphiSZb1u6I0nFn6KpZg=:d29ybGQ="
                );
            }));
        }
        {
            let credential = credential.clone();
            threads.push(thread::spawn(move || {
                assert_eq!(
                    credential.get().unwrap().sign_with_data(b"-test"),
                    "abcdefghklmnopq:HlxenSSP_6BbaYNzx1fyeyw8v1Y=:LXRlc3Q="
                );
                assert_eq!(
                    credential.get().unwrap().sign_with_data(b"ba#a-"),
                    "abcdefghklmnopq:kwzeJrFziPDMO4jv3DKVLDyqud0=:YmEjYS0="
                );
            }));
        }
        threads
            .into_iter()
            .for_each(|thread| thread.join().unwrap());
        Ok(())
    }

    #[inline]
    fn get_static_credential() -> impl CredentialProvider {
        StaticCredentialProvider::new("abcdefghklmnopq", "1234567890")
    }
}
