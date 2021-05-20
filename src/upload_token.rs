use crate::{
    credential::CredentialProvider,
    upload_policy::{UploadPolicy, UploadPolicyBuilder},
};
use once_cell::sync::OnceCell;
use std::{
    any::Any,
    borrow::Cow,
    fmt,
    io::{Error as IOError, Result as IOResult},
    time::Duration,
};
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub(super) enum ParseError {
    /// 上传凭证格式错误
    #[error("Invalid upload token format")]
    InvalidUploadTokenFormat,
    /// 上传凭证 Base64 解码错误
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    /// 上传凭证 JSON 解析错误
    #[error("JSON decode error: {0}")]
    JsonDecodeError(#[from] serde_json::Error),
    /// 上传凭证获取认证信息错误
    #[error("Credential get error: {0}")]
    CredentialGetError(#[from] IOError),
}
pub(super) type ParseResult<T> = Result<T, ParseError>;

pub(super) trait UploadTokenProvider: Any + fmt::Debug + Sync + Send {
    fn access_key(&self) -> ParseResult<Cow<str>>;
    fn policy(&self) -> ParseResult<Cow<UploadPolicy>>;
    fn to_string(&self) -> IOResult<Cow<str>>;
    fn as_upload_token_provider(&self) -> &dyn UploadTokenProvider;
    fn as_any(&self) -> &dyn Any;
}

pub(super) struct StaticUploadTokenProvider {
    upload_token: Box<str>,
    policy: OnceCell<UploadPolicy>,
    access_key: OnceCell<Box<str>>,
}

impl StaticUploadTokenProvider {
    #[inline]
    pub(super) fn new(upload_token: impl Into<String>) -> Self {
        Self {
            upload_token: upload_token.into().into_boxed_str(),
            policy: OnceCell::new(),
            access_key: OnceCell::new(),
        }
    }
}

impl fmt::Debug for StaticUploadTokenProvider {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StaticUploadTokenProvider")
            .field("upload_token", &self.upload_token)
            .finish()
    }
}

impl UploadTokenProvider for StaticUploadTokenProvider {
    fn access_key(&self) -> ParseResult<Cow<str>> {
        self.access_key
            .get_or_try_init(|| {
                self.upload_token
                    .find(':')
                    .map(|i| self.upload_token.split_at(i).0.to_owned().into())
                    .ok_or(ParseError::InvalidUploadTokenFormat)
            })
            .map(|access_key| access_key.as_ref().into())
    }

    fn policy(&self) -> ParseResult<Cow<UploadPolicy>> {
        self.policy
            .get_or_try_init(|| {
                let encoded_policy = self
                    .upload_token
                    .splitn(3, ':')
                    .last()
                    .ok_or(ParseError::InvalidUploadTokenFormat)?;
                let decoded_policy = base64::decode(encoded_policy.as_bytes())
                    .map_err(ParseError::Base64DecodeError)?;
                UploadPolicy::from_json(&decoded_policy).map_err(ParseError::JsonDecodeError)
            })
            .map(|policy| policy.into())
    }

    #[inline]
    fn to_string(&self) -> IOResult<Cow<str>> {
        Ok(Cow::Borrowed(&self.upload_token))
    }

    #[inline]
    fn as_upload_token_provider(&self) -> &dyn UploadTokenProvider {
        self
    }

    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(super) struct FromUploadPolicy {
    upload_policy: UploadPolicy,
    credential: Box<dyn CredentialProvider>,
    upload_token: OnceCell<Box<str>>,
}

impl FromUploadPolicy {
    #[inline]
    pub(super) fn new(
        upload_policy: UploadPolicy,
        credential: Box<dyn CredentialProvider>,
    ) -> Self {
        Self {
            upload_policy,
            credential,
            upload_token: OnceCell::new(),
        }
    }
}

impl fmt::Debug for FromUploadPolicy {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FromUploadPolicy")
            .field("upload_policy", &self.upload_policy)
            .finish()
    }
}

impl UploadTokenProvider for FromUploadPolicy {
    #[inline]
    fn access_key(&self) -> ParseResult<Cow<str>> {
        Ok(self.credential.get()?.into_pair().0)
    }

    #[inline]
    fn policy(&self) -> ParseResult<Cow<UploadPolicy>> {
        Ok(Cow::Borrowed(&self.upload_policy))
    }

    fn to_string(&self) -> IOResult<Cow<str>> {
        let upload_token = self.upload_token.get_or_try_init::<_, IOError>(|| {
            Ok(self
                .credential
                .get()?
                .sign_with_data(self.upload_policy.as_json().as_bytes())
                .into_boxed_str())
        })?;
        Ok(Cow::Borrowed(upload_token))
    }

    #[inline]
    fn as_upload_token_provider(&self) -> &dyn UploadTokenProvider {
        self
    }

    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(super) struct BucketUploadTokenProvider {
    bucket: Cow<'static, str>,
    upload_token_lifetime: Duration,
    credential: Box<dyn CredentialProvider>,
}

impl BucketUploadTokenProvider {
    #[inline]
    pub(super) fn new(
        bucket: impl Into<Cow<'static, str>>,
        upload_token_lifetime: Duration,
        credential: Box<dyn CredentialProvider>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            upload_token_lifetime,
            credential,
        }
    }
}

impl fmt::Debug for BucketUploadTokenProvider {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BucketUploadTokenProvider")
            .field("bucket", &self.bucket)
            .field("upload_token_lifetime", &self.upload_token_lifetime)
            .finish()
    }
}

impl UploadTokenProvider for BucketUploadTokenProvider {
    #[inline]
    fn access_key(&self) -> ParseResult<Cow<str>> {
        Ok(self.credential.get()?.into_pair().0)
    }

    fn policy(&self) -> ParseResult<Cow<UploadPolicy>> {
        Ok(UploadPolicyBuilder::new_policy_for_bucket(
            self.bucket.to_string(),
            self.upload_token_lifetime,
        )
        .build()
        .into())
    }

    fn to_string(&self) -> IOResult<Cow<str>> {
        let upload_token = self.credential.get()?.sign_with_data(
            UploadPolicyBuilder::new_policy_for_bucket(
                self.bucket.to_string(),
                self.upload_token_lifetime,
            )
            .build()
            .as_json()
            .as_bytes(),
        );
        Ok(upload_token.into())
    }

    #[inline]
    fn as_upload_token_provider(&self) -> &dyn UploadTokenProvider {
        self
    }

    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }
}
