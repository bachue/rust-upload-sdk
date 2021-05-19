use crate::{
    base64::urlsafe_encode,
    config::HTTP_CLIENT,
    error::{json_decode_response, HTTPCallError, HTTPCallResult},
    host_selector::{HostInfo, HostSelector},
    upload_token::UploadTokenProvider,
};
use digest::generic_array::GenericArray;
use log::{debug, error, info, warn};
use md5::{Digest, Md5};
use reqwest::{
    blocking::{Body as ReqwestBody, RequestBuilder as HTTPRequestBuilder},
    header::{HeaderName, AUTHORIZATION},
    Method, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JSONValue;
use std::{borrow::Cow, collections::HashMap, io::Read, sync::Arc, thread::sleep, time::Duration};
use tap::prelude::*;

pub(super) struct UploadAPICaller {
    inner: Arc<UploadAPICallerInner>,
}

struct UploadAPICallerInner {
    up_selector: HostSelector,
    upload_token_provider: Arc<dyn UploadTokenProvider>,
    tries: usize,
}

#[derive(Debug, Clone)]
pub(super) struct InitPartsRequest {
    bucket_name: String,
    object_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct InitPartsResponse {
    response_body: InitPartsResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct InitPartsResponseBody {
    upload_id: String,
}

#[derive(Debug, Clone)]
pub(super) struct UploadPartRequest<GetReader: Fn() -> (Box<dyn Read + Send>, u64)> {
    bucket_name: String,
    object_name: Option<String>,
    upload_id: String,
    part_number: u32,
    part_reader: GetReader,
    part_md5: GenericArray<u8, <Md5 as Digest>::OutputSize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct UploadPartResponseBody {
    etag: String,
    md5: String,
}

#[derive(Debug, Clone)]
pub(super) struct UploadPartResponse {
    response_body: UploadPartResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CompletePartInfo {
    etag: String,
    part_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CompletePartsRequestBody {
    parts: Vec<CompletePartInfo>,
    fname: Option<String>,

    #[serde(rename(serialize = "mimeType", deserialize = "mimeType"))]
    mime_type: Option<String>,

    metadata: Option<HashMap<String, String>>,

    #[serde(rename(serialize = "customVars", deserialize = "customVars"))]
    custom_vars: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub(super) struct CompletePartsRequest {
    bucket_name: String,
    object_name: Option<String>,
    upload_id: String,
    request_body: CompletePartsRequestBody,
}

#[derive(Debug, Clone)]
pub(super) struct CompletePartsResponse {
    response_body: JSONValue,
}

const CONTENT_MD5: &str = "content-md5";

impl UploadAPICaller {
    pub(super) fn init_parts(
        &self,
        request: InitPartsRequest,
    ) -> HTTPCallResult<InitPartsResponse> {
        self.with_retries(
            &Method::POST,
            &format!(
                "buckets/{}/objects/{}/uploads",
                request.bucket_name,
                encode_object_name(request.object_name.as_ref().map(|s| s.as_str()))
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] init_parts url: {}", tries, url);
                let response_body: InitPartsResponseBody = request_builder
                    .send()
                    .map_err(HTTPCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(|resp: &InitPartsResponseBody| {
                        info!(
                            "[{}] init_parts ok url: {}, upload_id: {}",
                            tries, url, resp.upload_id
                        );
                    })
                    .tap_err(|err| {
                        warn!("[{}] init_parts error url: {}, error: {}", tries, url, err);
                    })?;
                Ok(InitPartsResponse { response_body })
            },
            |err, url| {
                error!("final failed init_parts url = {}, error: {:?}", url, err,);
            },
        )
    }

    pub(super) fn upload_part<GetReader: Fn() -> (Box<dyn Read + Send>, u64)>(
        &self,
        request: UploadPartRequest<GetReader>,
    ) -> HTTPCallResult<UploadPartResponse> {
        self.with_retries(
            &Method::PUT,
            &format!(
                "buckets/{}/objects/{}/uploads/{}/{}",
                request.bucket_name,
                encode_object_name(request.object_name.as_ref().map(|s| s.as_str())),
                request.upload_id,
                request.part_number,
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] upload_part url: {}", tries, url);
                let request_body = {
                    let (body_reader, body_size) = (request.part_reader)();
                    ReqwestBody::sized(body_reader, body_size)
                };
                let response_body: UploadPartResponseBody = request_builder
                    .header(
                        HeaderName::from_static(CONTENT_MD5),
                        hex::encode(request.part_md5),
                    )
                    .body(request_body)
                    .send()
                    .map_err(HTTPCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(|resp: &UploadPartResponseBody| {
                        info!(
                            "[{}] upload_part ok url: {}, etag: {}, md5: {}",
                            tries, url, resp.etag, resp.md5,
                        );
                    })
                    .tap_err(|err| {
                        warn!("[{}] upload_part error url: {}, error: {}", tries, url, err);
                    })?;
                Ok(UploadPartResponse { response_body })
            },
            |err, url| {
                error!("final failed upload_part url = {}, error: {:?}", url, err,);
            },
        )
    }

    pub(super) fn complete_parts(
        &self,
        request: CompletePartsRequest,
    ) -> HTTPCallResult<CompletePartsResponse> {
        self.with_retries(
            &Method::POST,
            &format!(
                "buckets/{}/objects/{}/uploads/{}",
                request.bucket_name,
                encode_object_name(request.object_name.as_ref().map(|s| s.as_str())),
                request.upload_id,
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] complete_parts url: {}", tries, url);
                let response_body: JSONValue = request_builder
                    .json(&request.request_body)
                    .send()
                    .map_err(HTTPCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(|resp: &JSONValue| {
                        info!(
                            "[{}] complete_parts ok url: {}, hash: {:?}, key: {:?}",
                            tries,
                            url,
                            resp.get("hash").and_then(|v| v.as_str()),
                            resp.get("key").and_then(|v| v.as_str()),
                        );
                    })
                    .tap_err(|err| {
                        warn!(
                            "[{}] complete_parts error url: {}, error: {}",
                            tries, url, err
                        );
                    })?;
                Ok(CompletePartsResponse { response_body })
            },
            |err, url| {
                error!(
                    "final failed complete_parts url = {}, error: {:?}",
                    url, err,
                );
            },
        )
    }

    fn with_retries<T>(
        &self,
        method: &Method,
        path: &str,
        mut for_each_url: impl FnMut(usize, HTTPRequestBuilder, &str, &HostInfo) -> HTTPCallResult<T>,
        final_error: impl FnOnce(&HTTPCallError, &str),
    ) -> HTTPCallResult<T> {
        assert!(self.inner.tries > 0);

        for tries in 0..self.inner.tries {
            sleep_before_retry(tries);
            let last_try = self.inner.tries - tries <= 1;
            let chosen_up_info = self.inner.up_selector.select_host();
            let url = format!("{}/{}", chosen_up_info.host, path);
            let request_builder = HTTP_CLIENT
                .read()
                .unwrap()
                .request(method.to_owned(), url.to_owned())
                .header(
                    AUTHORIZATION,
                    &format!("UpToken {}", self.inner.upload_token_provider.to_string()?),
                )
                .timeout(chosen_up_info.timeout);
            match for_each_url(tries, request_builder, &url, &chosen_up_info) {
                Ok(result) => {
                    self.inner.up_selector.reward(&chosen_up_info.host);
                    return Ok(result);
                }
                Err(err) => {
                    let punished = self.inner.up_selector.punish(&chosen_up_info.host, &err);
                    if !punished || last_try {
                        final_error(&err, url.as_str());
                        return Err(err);
                    }
                }
            }
        }
        unreachable!();

        #[inline]
        fn sleep_before_retry(tries: usize) {
            if tries >= 3 {
                sleep(Duration::from_secs(tries as u64));
            }
        }
    }

    #[inline]
    fn increase_timeout_power_if_needed(&self, chosen_info: &HostInfo, err: &HTTPCallError) {
        match err {
            HTTPCallError::ReqwestError(err) if err.is_timeout() => self
                .inner
                .up_selector
                .increase_timeout_power_by(&chosen_info.host, chosen_info.timeout_power),
            _ => {}
        }
    }
}

fn encode_object_name(object_name: Option<&str>) -> Cow<'static, str> {
    if let Some(object_name) = object_name {
        urlsafe_encode(object_name.as_bytes()).into()
    } else {
        "~".into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        credential::StaticCredentialProvider, host_selector::HostSelectorBuilder,
        upload_token::BucketUploadTokenProvider,
    };

    use super::*;
    use futures::channel::oneshot::channel;
    use serde_json::json;
    use std::{
        boxed::Box,
        io::Cursor,
        sync::{
            atomic::{AtomicUsize, Ordering::Relaxed},
            Arc,
        },
    };
    use tokio::task::{spawn, spawn_blocking};
    use warp::{
        filters::body::json as json_as_body,
        header,
        http::{HeaderValue, StatusCode},
        path,
        reply::Response,
        Filter,
    };

    macro_rules! starts_with_server {
        ($addr:ident, $routes:ident, $code:block) => {{
            let (tx, rx) = channel();
            let ($addr, server) =
                warp::serve($routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async move {
                    rx.await.ok();
                });
            let handler = spawn(server);
            $code;
            tx.send(()).ok();
            handler.await.ok();
        }};
    }

    #[tokio::test]
    async fn test_init_parts() -> anyhow::Result<()> {
        env_logger::try_init().ok();

        let routes = path!("buckets" / String / "objects" / String / "uploads")
            .and(header::value(AUTHORIZATION.as_str()))
            .map(
                |bucket_name: String, object_name: String, authorization: HeaderValue| {
                    assert_eq!(bucket_name, "test-bucket");
                    assert_eq!(object_name, encode_object_name(Some("test-key")));
                    assert!(authorization
                        .to_str()
                        .unwrap()
                        .starts_with("UpToken 1234567890:"));
                    Response::new(
                        serde_json::to_vec(&json!({ "upload_id": "fakeuploadid" }))
                            .unwrap()
                            .into(),
                    )
                },
            );
        starts_with_server!(addr, routes, {
            let caller = UploadAPICaller {
                inner: Arc::new(UploadAPICallerInner {
                    up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                    upload_token_provider: Arc::new(BucketUploadTokenProvider::new(
                        "test-bucket",
                        Duration::from_secs(60),
                        Box::new(get_credential()),
                    )),
                    tries: 1,
                }),
            };
            spawn_blocking::<_, HTTPCallResult<_>>(move || {
                let response = caller.init_parts(InitPartsRequest {
                    bucket_name: "test-bucket".into(),
                    object_name: Some("test-key".into()),
                })?;
                assert_eq!(response.response_body.upload_id, "fakeuploadid");
                Ok(())
            })
            .await??;
        });
        Ok(())
    }

    #[tokio::test]
    async fn test_init_parts_with_error() -> anyhow::Result<()> {
        env_logger::try_init().ok();
        let called_times = Arc::new(AtomicUsize::new(0));

        let routes = {
            let called_times = called_times.to_owned();
            path!("buckets" / String / "objects" / String / "uploads")
                .and(header::value(AUTHORIZATION.as_str()))
                .map(
                    move |bucket_name: String, object_name: String, authorization: HeaderValue| {
                        assert_eq!(bucket_name, "test-bucket");
                        assert_eq!(object_name, "~");
                        assert!(authorization
                            .to_str()
                            .unwrap()
                            .starts_with("UpToken 1234567890:"));
                        called_times.fetch_add(1, Relaxed);
                        Response::new(
                            serde_json::to_vec(&json!({ "error": "bad token" }))
                                .unwrap()
                                .into(),
                        )
                        .tap_mut(|response| *response.status_mut() = StatusCode::UNAUTHORIZED)
                    },
                )
        };
        starts_with_server!(addr, routes, {
            let caller = UploadAPICaller {
                inner: Arc::new(UploadAPICallerInner {
                    up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                    upload_token_provider: Arc::new(BucketUploadTokenProvider::new(
                        "test-bucket",
                        Duration::from_secs(60),
                        Box::new(get_credential()),
                    )),
                    tries: 3,
                }),
            };
            {
                let called_times = called_times.to_owned();
                spawn_blocking::<_, HTTPCallResult<_>>(move || {
                    let err = caller
                        .init_parts(InitPartsRequest {
                            bucket_name: "test-bucket".into(),
                            object_name: None,
                        })
                        .unwrap_err();
                    match err {
                        HTTPCallError::StatusCodeError {
                            status_code,
                            error_message,
                            ..
                        } => {
                            assert_eq!(status_code, StatusCode::UNAUTHORIZED);
                            assert_eq!(error_message, Some("bad token".into()));
                        }
                        _ => unreachable!(),
                    }
                    assert_eq!(called_times.load(Relaxed), 3);
                    Ok(())
                })
                .await??;
            }
            called_times.store(0, Relaxed);

            let caller = UploadAPICaller {
                inner: Arc::new(UploadAPICallerInner {
                    up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)])
                        .should_punish_callback(Box::new(|err| match err {
                            HTTPCallError::ReqwestError(err) if err.is_builder() => false,
                            HTTPCallError::StatusCodeError { status_code, .. } => {
                                !status_code.is_client_error()
                            }
                            _ => true,
                        }))
                        .build(),
                    upload_token_provider: Arc::new(BucketUploadTokenProvider::new(
                        "test-bucket",
                        Duration::from_secs(60),
                        Box::new(get_credential()),
                    )),
                    tries: 3,
                }),
            };
            spawn_blocking::<_, HTTPCallResult<_>>(move || {
                let err = caller
                    .init_parts(InitPartsRequest {
                        bucket_name: "test-bucket".into(),
                        object_name: None,
                    })
                    .unwrap_err();
                match err {
                    HTTPCallError::StatusCodeError {
                        status_code,
                        error_message,
                        ..
                    } => {
                        assert_eq!(status_code, StatusCode::UNAUTHORIZED);
                        assert_eq!(error_message, Some("bad token".into()));
                    }
                    _ => unreachable!(),
                }
                assert_eq!(called_times.load(Relaxed), 1);
                Ok(())
            })
            .await??;
        });

        Ok(())
    }

    #[tokio::test]
    async fn test_upload_part() -> anyhow::Result<()> {
        env_logger::try_init().ok();

        const PART_CONTENT: &[u8] = b"01234567890";
        let md5 = {
            let mut hasher = Md5::new();
            hasher.update(PART_CONTENT);
            hasher.finalize()
        };

        let routes = {
            let md5 = md5.to_owned();
            path!("buckets" / String / "objects" / String / "uploads" / String / u32)
                .and(header::value(AUTHORIZATION.as_str()))
                .and(header::value(CONTENT_MD5))
                .map(
                    move |bucket_name: String,
                          object_name: String,
                          upload_id: String,
                          part_number: u32,
                          authorization: HeaderValue,
                          content_md5: HeaderValue| {
                        assert_eq!(bucket_name, "test-bucket");
                        assert_eq!(object_name, encode_object_name(Some("test-key")));
                        assert_eq!(upload_id, "fakeuploadid");
                        assert_eq!(part_number, 1u32);
                        assert!(authorization
                            .to_str()
                            .unwrap()
                            .starts_with("UpToken 1234567890:"));
                        assert_eq!(content_md5.to_str().unwrap(), hex::encode(md5));
                        Response::new(
                            serde_json::to_vec(&json!({ "etag": "fakeetag_1", "md5": content_md5
                        .to_str()
                        .unwrap() }))
                            .unwrap()
                            .into(),
                        )
                    },
                )
        };
        starts_with_server!(addr, routes, {
            let caller = UploadAPICaller {
                inner: Arc::new(UploadAPICallerInner {
                    up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                    upload_token_provider: Arc::new(BucketUploadTokenProvider::new(
                        "test-bucket",
                        Duration::from_secs(60),
                        Box::new(get_credential()),
                    )),
                    tries: 1,
                }),
            };
            spawn_blocking::<_, HTTPCallResult<_>>(move || {
                let response = caller.upload_part(UploadPartRequest {
                    bucket_name: "test-bucket".into(),
                    object_name: Some("test-key".into()),
                    upload_id: "fakeuploadid".into(),
                    part_number: 1,
                    part_reader: || {
                        (
                            Box::new(Cursor::new(PART_CONTENT)),
                            PART_CONTENT.len() as u64,
                        )
                    },
                    part_md5: md5.to_owned(),
                })?;
                assert_eq!(response.response_body.etag, "fakeetag_1");
                assert_eq!(response.response_body.md5, hex::encode(md5));
                Ok(())
            })
            .await??;
        });
        Ok(())
    }

    #[tokio::test]
    async fn test_complete_parts() -> anyhow::Result<()> {
        env_logger::try_init().ok();

        let routes = path!("buckets" / String / "objects" / String / "uploads" / String)
            .and(header::value(AUTHORIZATION.as_str()))
            .and(json_as_body())
            .map(
                |bucket_name: String,
                 object_name: String,
                 upload_id: String,
                 authorization: HeaderValue,
                 body: CompletePartsRequestBody| {
                    assert_eq!(bucket_name, "test-bucket");
                    assert_eq!(object_name, encode_object_name(Some("~")));
                    assert_eq!(upload_id, "fakeuploadid");
                    assert!(authorization
                        .to_str()
                        .unwrap()
                        .starts_with("UpToken 1234567890:"));
                    assert_eq!(body.parts.len(), 3);
                    Response::new(
                        serde_json::to_vec(&json!({ "hash": "fakeetag" }))
                            .unwrap()
                            .into(),
                    )
                },
            );
        starts_with_server!(addr, routes, {
            let caller = UploadAPICaller {
                inner: Arc::new(UploadAPICallerInner {
                    up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                    upload_token_provider: Arc::new(BucketUploadTokenProvider::new(
                        "test-bucket",
                        Duration::from_secs(60),
                        Box::new(get_credential()),
                    )),
                    tries: 1,
                }),
            };
            spawn_blocking::<_, HTTPCallResult<_>>(move || {
                let response = caller.complete_parts(CompletePartsRequest {
                    bucket_name: "test-bucket".into(),
                    object_name: Some("~".into()),
                    upload_id: "fakeuploadid".into(),
                    request_body: CompletePartsRequestBody {
                        parts: vec![
                            CompletePartInfo {
                                etag: "fakeetag_1".to_string(),
                                part_number: 1,
                            },
                            CompletePartInfo {
                                etag: "fakeetag_2".to_string(),
                                part_number: 2,
                            },
                            CompletePartInfo {
                                etag: "fakeetag_3".to_string(),
                                part_number: 3,
                            },
                        ],
                        custom_vars: None,
                        fname: None,
                        mime_type: None,
                        metadata: None,
                    },
                })?;
                assert_eq!(
                    response.response_body.get("hash").and_then(|s| s.as_str()),
                    Some("fakeetag")
                );
                assert!(response.response_body.get("key").is_none());
                Ok(())
            })
            .await??;
        });
        Ok(())
    }

    #[inline]
    fn get_credential() -> StaticCredentialProvider {
        StaticCredentialProvider::new("1234567890", "abcdefghijk")
    }
}
