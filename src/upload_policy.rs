use serde_json::{
    json, map::Keys as JSONMapKeys, value::Index as JSONValueIndex, Value as JSONValue,
};
use std::{
    fmt,
    time::{Duration, SystemTime},
};

const SCOPE_KEY: &str = "scope";
const DEADLINE_KEY: &str = "deadline";

#[derive(Clone, Eq, PartialEq)]
pub(super) struct UploadPolicy {
    inner: JSONValue,
}

impl UploadPolicy {
    #[inline]
    pub(super) fn new_for_bucket(
        bucket: impl Into<String>,
        upload_token_lifetime: Duration,
    ) -> UploadPolicyBuilder {
        UploadPolicyBuilder::new_policy_for_bucket(bucket, upload_token_lifetime)
    }

    #[inline]
    pub(super) fn new_for_object(
        bucket: impl Into<String>,
        key: impl AsRef<str>,
        upload_token_lifetime: Duration,
    ) -> UploadPolicyBuilder {
        UploadPolicyBuilder::new_policy_for_object(bucket, key, upload_token_lifetime)
    }

    #[inline]
    pub(super) fn bucket(&self) -> Option<&str> {
        self.get(SCOPE_KEY)
            .as_ref()
            .and_then(|s| s.as_str())
            .and_then(|s| s.splitn(2, ':').next())
    }

    #[inline]
    pub(super) fn key(&self) -> Option<&str> {
        self.get(SCOPE_KEY)
            .as_ref()
            .and_then(|v| v.as_str())
            .and_then(|s| s.splitn(2, ':').nth(1))
    }

    #[inline]
    pub(super) fn token_deadline(&self) -> Option<SystemTime> {
        self.get(DEADLINE_KEY).and_then(|v| v.as_u64()).map(|t| {
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(t))
                .unwrap()
        })
    }

    #[inline]
    pub(super) fn as_json(&self) -> String {
        serde_json::to_string(&self.inner).unwrap()
    }

    #[inline]
    pub(super) fn from_json(json: impl AsRef<[u8]>) -> serde_json::Result<UploadPolicy> {
        serde_json::from_slice(json.as_ref()).map(|inner| UploadPolicy { inner })
    }

    #[inline]
    pub(super) fn get(&self, key: impl JSONValueIndex) -> Option<&JSONValue> {
        self.inner.get(key)
    }

    #[inline]
    pub(super) fn keys(&self) -> JSONMapKeys {
        self.inner.as_object().unwrap().keys()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UploadPolicyBuilder {
    inner: JSONValue,
}

impl From<UploadPolicy> for UploadPolicyBuilder {
    #[inline]
    fn from(policy: UploadPolicy) -> Self {
        Self {
            inner: policy.inner,
        }
    }
}

impl UploadPolicyBuilder {
    #[inline]
    pub(super) fn new_policy_for_bucket(
        bucket: impl Into<String>,
        upload_token_lifetime: Duration,
    ) -> Self {
        let mut policy = Self {
            inner: json!({
                SCOPE_KEY: bucket.into().into_boxed_str(),
            }),
        };
        policy.token_lifetime(upload_token_lifetime);
        policy
    }

    pub(super) fn new_policy_for_object(
        bucket: impl Into<String>,
        key: impl AsRef<str>,
        upload_token_lifetime: Duration,
    ) -> Self {
        let mut policy = Self {
            inner: json!({
                SCOPE_KEY: bucket.into() + ":" + key.as_ref(),
            }),
        };
        policy.token_lifetime(upload_token_lifetime);
        policy
    }

    fn token_lifetime(&mut self, lifetime: Duration) -> &mut Self {
        self.set(
            DEADLINE_KEY.into(),
            JSONValue::Number(
                SystemTime::now()
                    .checked_add(lifetime)
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|t| t.as_secs())
                    .unwrap_or(u64::max_value())
                    .into(),
            ),
        )
    }

    #[inline]
    fn set(&mut self, k: String, v: JSONValue) -> &mut Self {
        self.inner.as_object_mut().unwrap().insert(k, v);
        self
    }

    #[inline]
    pub(super) fn build(self) -> UploadPolicy {
        UploadPolicy { inner: self.inner }
    }
}

impl fmt::Debug for UploadPolicyBuilder {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl fmt::Debug for UploadPolicy {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{boxed::Box, error::Error, result::Result};

    #[test]
    fn test_build_upload_policy_for_bucket() -> Result<(), Box<dyn Error>> {
        let policy =
            UploadPolicyBuilder::new_policy_for_bucket("test_bucket", Duration::from_secs(3600))
                .build();
        let now = SystemTime::now();
        let one_hour_later = now + Duration::from_secs(60 * 60);
        assert_eq!(policy.bucket(), Some("test_bucket"));
        assert_eq!(policy.key(), None);
        assert!(
            one_hour_later.duration_since(SystemTime::UNIX_EPOCH)?
                - policy
                    .token_deadline()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                < Duration::from_secs(5)
        );

        assert_eq!(policy.keys().len(), 2);
        assert_eq!(policy.get("scope"), Some(&json!("test_bucket")));
        assert!(
            one_hour_later.duration_since(SystemTime::UNIX_EPOCH)?
                - Duration::from_secs(policy.get("deadline").unwrap().as_u64().unwrap())
                < Duration::from_secs(5)
        );
        Ok(())
    }

    #[test]
    fn test_build_upload_policy_for_object() -> Result<(), Box<dyn Error>> {
        let policy = UploadPolicyBuilder::new_policy_for_object(
            "test_bucket",
            "test:object",
            Duration::from_secs(3600),
        )
        .build();
        let now = SystemTime::now();
        let one_hour_later = now + Duration::from_secs(60 * 60);
        assert_eq!(policy.bucket(), Some("test_bucket"));
        assert_eq!(policy.key(), Some("test:object"));
        assert!(
            one_hour_later.duration_since(SystemTime::UNIX_EPOCH)?
                - policy
                    .token_deadline()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                < Duration::from_secs(5)
        );

        assert_eq!(policy.keys().len(), 2);
        assert_eq!(policy.get("scope"), Some(&json!("test_bucket:test:object")));
        assert!(
            one_hour_later.duration_since(SystemTime::UNIX_EPOCH)?
                - Duration::from_secs(policy.get("deadline").unwrap().as_u64().unwrap())
                < Duration::from_secs(5)
        );
        Ok(())
    }
}
