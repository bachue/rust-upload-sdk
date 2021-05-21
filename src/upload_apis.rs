use crate::{
    base64::urlsafe_encode,
    config::HTTP_CLIENT,
    error::{json_decode_response, HttpCallError, HttpCallResult},
    host_selector::{HostInfo, HostSelector},
    upload_token::UploadTokenProvider,
    utils::{PartReader, UploadSource},
};
use log::{debug, error, info, warn};
use reqwest::{
    blocking::{
        multipart::{Form, Part},
        RequestBuilder as HTTPRequestBuilder,
    },
    header::{HeaderName, HeaderValue, AUTHORIZATION},
    Method, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JSONValue;
use std::{borrow::Cow, collections::HashMap, thread::sleep, time::Duration};
use tap::prelude::*;

#[derive(Debug)]
pub(super) struct UploadApiCaller {
    up_selector: HostSelector,
    upload_token_provider: Box<dyn UploadTokenProvider>,
    tries: usize,
}

impl UploadApiCaller {
    #[inline]
    pub(super) fn new(
        up_selector: HostSelector,
        upload_token_provider: Box<dyn UploadTokenProvider>,
        tries: usize,
    ) -> Self {
        Self {
            up_selector,
            upload_token_provider,
            tries,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct FormUploadRequest<'a> {
    object_name: Option<&'a str>,
    file_name: Option<&'a str>,
    mime_type: Option<&'a str>,
    upload_source: UploadSource,
    metadata: Option<HashMap<String, String>>,
    custom_vars: Option<HashMap<String, String>>,
}

impl<'a> FormUploadRequest<'a> {
    #[inline]
    pub(super) fn new(
        object_name: Option<&'a str>,
        file_name: Option<&'a str>,
        mime_type: Option<&'a str>,
        upload_source: UploadSource,
        metadata: Option<HashMap<String, String>>,
        custom_vars: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            object_name,
            file_name,
            mime_type,
            upload_source,
            metadata,
            custom_vars,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct FormUploadResponse {
    response_body: JSONValue,
}

impl FormUploadResponse {
    #[inline]
    pub(super) fn response_body_mut(&mut self) -> &mut JSONValue {
        &mut self.response_body
    }

    #[inline]
    pub(super) fn response_body(&self) -> &JSONValue {
        &self.response_body
    }
}

#[derive(Debug, Clone)]
pub(super) struct InitPartsRequest<'a> {
    bucket_name: &'a str,
    object_name: Option<&'a str>,
}

impl<'a> InitPartsRequest<'a> {
    #[inline]
    pub(super) fn new(bucket_name: &'a str, object_name: Option<&'a str>) -> Self {
        Self {
            bucket_name,
            object_name,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct InitPartsResponse {
    response_body: InitPartsResponseBody,
}

impl InitPartsResponse {
    #[inline]
    pub(super) fn response_body(&self) -> &InitPartsResponseBody {
        &self.response_body
    }

    #[inline]
    pub(super) fn response_body_mut(&mut self) -> &mut InitPartsResponseBody {
        &mut self.response_body
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct InitPartsResponseBody {
    #[serde(rename(serialize = "uploadId", deserialize = "uploadId"))]
    upload_id: String,
}

impl InitPartsResponseBody {
    #[inline]
    pub(super) fn upload_id(&self) -> &str {
        &self.upload_id
    }

    #[inline]
    pub(super) fn upload_id_mut(&mut self) -> &mut String {
        &mut self.upload_id
    }
}

#[derive(Debug, Clone)]
pub(super) struct UploadPartRequest<'a> {
    bucket_name: &'a str,
    object_name: Option<&'a str>,
    upload_id: &'a str,
    part_number: u32,
    part_reader: PartReader,
}

impl<'a> UploadPartRequest<'a> {
    #[inline]
    pub(super) fn new(
        bucket_name: &'a str,
        object_name: Option<&'a str>,
        upload_id: &'a str,
        part_number: u32,
        part_reader: PartReader,
    ) -> Self {
        Self {
            bucket_name,
            object_name,
            upload_id,
            part_number,
            part_reader,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct UploadPartResponseBody {
    etag: String,
    md5: String,
}

impl UploadPartResponseBody {
    #[inline]
    pub(super) fn etag(&self) -> &str {
        &self.etag
    }

    #[inline]
    pub(super) fn md5(&self) -> &str {
        &self.md5
    }

    #[inline]
    pub(super) fn etag_mut(&mut self) -> &mut String {
        &mut self.etag
    }

    #[inline]
    pub(super) fn md5_mut(&mut self) -> &mut String {
        &mut self.md5
    }
}

#[derive(Debug, Clone)]
pub(super) struct UploadPartResponse {
    response_body: UploadPartResponseBody,
    uploaded: u64,
}

impl UploadPartResponse {
    #[inline]
    pub(super) fn response_body(&self) -> &UploadPartResponseBody {
        &self.response_body
    }

    #[inline]
    pub(super) fn response_body_mut(&mut self) -> &mut UploadPartResponseBody {
        &mut self.response_body
    }

    #[inline]
    pub(super) fn uploaded_mut(&mut self) -> &mut u64 {
        &mut self.uploaded
    }

    #[inline]
    pub(super) fn uploaded(&self) -> u64 {
        self.uploaded
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CompletePartInfo {
    etag: String,

    #[serde(rename(serialize = "partNumber", deserialize = "partNumber"))]
    part_number: u32,
}

impl CompletePartInfo {
    #[inline]
    pub(super) fn new(etag: String, part_number: u32) -> Self {
        Self { etag, part_number }
    }
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

impl CompletePartsRequestBody {
    #[inline]
    pub(super) fn new(
        parts: Vec<CompletePartInfo>,
        fname: Option<String>,
        mime_type: Option<String>,
        metadata: Option<HashMap<String, String>>,
        custom_vars: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            parts,
            fname,
            mime_type,
            metadata,
            custom_vars,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CompletePartsRequest<'a> {
    bucket_name: &'a str,
    object_name: Option<&'a str>,
    upload_id: &'a str,
    request_body: CompletePartsRequestBody,
}

impl<'a> CompletePartsRequest<'a> {
    #[inline]
    pub(super) fn new(
        bucket_name: &'a str,
        object_name: Option<&'a str>,
        upload_id: &'a str,
        request_body: CompletePartsRequestBody,
    ) -> Self {
        Self {
            bucket_name,
            object_name,
            upload_id,
            request_body,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CompletePartsResponse {
    response_body: JSONValue,
}

impl CompletePartsResponse {
    #[inline]
    pub(super) fn response_body_mut(&mut self) -> &mut JSONValue {
        &mut self.response_body
    }

    #[inline]
    pub(super) fn response_body(&self) -> &JSONValue {
        &self.response_body
    }
}

const CONTENT_MD5: &str = "content-md5";

impl UploadApiCaller {
    pub(super) fn form_upload(
        &self,
        request: &FormUploadRequest,
    ) -> HttpCallResult<FormUploadResponse> {
        self.with_retries(
            &Method::POST,
            "",
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] form_upload url: {}", tries, url);
                let form_data = {
                    let mut form_data = Form::new().text(
                        "token",
                        self.upload_token_provider.to_string()?.into_owned(),
                    );
                    if let Some(object_name) = request.object_name {
                        form_data = form_data.text("key", object_name.to_owned());
                    }

                    let (file_size, crc32) = request.upload_source.crc32()?;
                    form_data = form_data.text("crc32", crc32.to_string());
                    let mut file_part =
                        Part::reader_with_length(request.upload_source.reader(), file_size);
                    if let Some(file_name) = request.file_name {
                        file_part = file_part.file_name(file_name.to_owned());
                    }
                    if let Some(mime_str) = request.mime_type {
                        file_part = file_part.mime_str(mime_str)?;
                    }
                    form_data = form_data.part("file", file_part);
                    if let Some(metadata) = &request.metadata {
                        for (meta_key, meta_value) in metadata.iter() {
                            form_data = form_data
                                .text(format!("x-qn-meta-{}", meta_key), meta_value.to_owned());
                        }
                    }
                    if let Some(custom_vars) = &request.custom_vars {
                        for (var_name, var_value) in custom_vars.iter() {
                            form_data =
                                form_data.text(format!("x:{}", var_name), var_value.to_owned());
                        }
                    }
                    form_data
                };
                let response_body = request_builder
                    .multipart(form_data)
                    .send()
                    .map_err(HttpCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(|(_, request_id): &(JSONValue, Option<HeaderValue>)| {
                        info!(
                            "[{}] form_upload ok url: {}, request_id: {:?}",
                            tries, url, request_id,
                        );
                    })
                    .map(|(resp, _)| resp)
                    .tap_err(|err| {
                        warn!("[{}] form_upload error url: {}, error: {}", tries, url, err);
                    })?;
                Ok(FormUploadResponse { response_body })
            },
            |err, url| {
                error!("final failed form_upload url = {}, error: {:?}", url, err,);
            },
            &UploadApiCallerOption {
                add_upload_authorization: false,
            },
        )
    }

    pub(super) fn init_parts(
        &self,
        request: &InitPartsRequest,
    ) -> HttpCallResult<InitPartsResponse> {
        self.with_retries(
            &Method::POST,
            &format!(
                "buckets/{}/objects/{}/uploads",
                request.bucket_name,
                encode_object_name(request.object_name)
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] init_parts url: {}", tries, url);
                let response_body = request_builder
                    .send()
                    .map_err(HttpCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(
                        |(resp, request_id): &(InitPartsResponseBody, Option<HeaderValue>)| {
                            info!(
                                "[{}] init_parts ok url: {}, upload_id: {}, request_id: {:?}",
                                tries, url, resp.upload_id, request_id,
                            );
                        },
                    )
                    .map(|(resp, _)| resp)
                    .tap_err(|err| {
                        warn!("[{}] init_parts error url: {}, error: {}", tries, url, err);
                    })?;
                Ok(InitPartsResponse { response_body })
            },
            |err, url| {
                error!("final failed init_parts url = {}, error: {:?}", url, err,);
            },
            &Default::default(),
        )
    }

    pub(super) fn upload_part(
        &self,
        request: &UploadPartRequest,
    ) -> HttpCallResult<UploadPartResponse> {
        self.with_retries(
            &Method::PUT,
            &format!(
                "buckets/{}/objects/{}/uploads/{}/{}",
                request.bucket_name,
                encode_object_name(request.object_name),
                request.upload_id,
                request.part_number,
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] upload_part url: {}", tries, url);
                let (part_size, md5) = request.part_reader.md5()?;
                let response_body = request_builder
                    .header(HeaderName::from_static(CONTENT_MD5), hex::encode(md5))
                    .body(request.part_reader.body(part_size))
                    .send()
                    .map_err(HttpCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(
                        |(resp, request_id): &(UploadPartResponseBody, Option<HeaderValue>)| {
                            info!(
                                "[{}] upload_part ok url: {}, etag: {}, md5: {}, request_id: {:?}",
                                tries, url, resp.etag, resp.md5, request_id,
                            );
                        },
                    )
                    .map(|(resp, _)| resp)
                    .tap_err(|err| {
                        warn!("[{}] upload_part error url: {}, error: {}", tries, url, err);
                    })?;
                Ok(UploadPartResponse {
                    response_body,
                    uploaded: part_size,
                })
            },
            |err, url| {
                error!("final failed upload_part url = {}, error: {:?}", url, err,);
            },
            &Default::default(),
        )
    }

    pub(super) fn complete_parts(
        &self,
        request: &CompletePartsRequest,
    ) -> HttpCallResult<CompletePartsResponse> {
        self.with_retries(
            &Method::POST,
            &format!(
                "buckets/{}/objects/{}/uploads/{}",
                request.bucket_name,
                encode_object_name(request.object_name),
                request.upload_id,
            ),
            |tries, request_builder, url, chosen_info| {
                debug!("[{}] complete_parts url: {}", tries, url);
                let response_body = request_builder
                    .json(&request.request_body)
                    .send()
                    .map_err(HttpCallError::ReqwestError)
                    .tap_err(|err| self.increase_timeout_power_if_needed(chosen_info, err))
                    .and_then(|resp| {
                        if resp.status() == StatusCode::OK {
                            json_decode_response(resp)
                        } else {
                            Err(resp.into())
                        }
                    })
                    .tap_ok(|(resp, request_id): &(JSONValue, Option<HeaderValue>)| {
                        info!(
                            "[{}] complete_parts ok url: {}, hash: {:?}, key: {:?}, request_id: {:?}",
                            tries,
                            url,
                            resp.get("hash").and_then(|v| v.as_str()),
                            resp.get("key").and_then(|v| v.as_str()),
                            request_id,
                        );
                    })
                    .map(|(resp,_)|resp)
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
            &Default::default(),
        )
    }

    fn with_retries<T>(
        &self,
        method: &Method,
        path: &str,
        mut for_each_url: impl FnMut(usize, HTTPRequestBuilder, &str, &HostInfo) -> HttpCallResult<T>,
        final_error: impl FnOnce(&HttpCallError, &str),
        option: &UploadApiCallerOption,
    ) -> HttpCallResult<T> {
        assert!(self.tries > 0);

        for tries in 0..self.tries {
            sleep_before_retry(tries);
            let last_try = self.tries - tries <= 1;
            let chosen_up_info = self.up_selector.select_host();
            let url = format!("{}/{}", chosen_up_info.host, path);
            let mut request_builder = HTTP_CLIENT
                .read()
                .unwrap()
                .request(method.to_owned(), url.to_owned())
                .timeout(chosen_up_info.timeout);
            if option.add_upload_authorization {
                let upload_token = self.upload_token_provider.to_string()?;
                request_builder =
                    request_builder.header(AUTHORIZATION, &format!("UpToken {}", upload_token));
            }
            match for_each_url(tries, request_builder, &url, &chosen_up_info) {
                Ok(result) => {
                    self.up_selector.reward(&chosen_up_info.host);
                    return Ok(result);
                }
                Err(err) => {
                    let punished = self.up_selector.punish(&chosen_up_info.host, &err);
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
    fn increase_timeout_power_if_needed(&self, chosen_info: &HostInfo, err: &HttpCallError) {
        match err {
            HttpCallError::ReqwestError(err) if err.is_timeout() => self
                .up_selector
                .increase_timeout_power_by(&chosen_info.host, chosen_info.timeout_power),
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
struct UploadApiCallerOption {
    add_upload_authorization: bool,
}

impl Default for UploadApiCallerOption {
    #[inline]
    fn default() -> Self {
        Self {
            add_upload_authorization: true,
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
        upload_token::BucketUploadTokenProvider, utils::UploadSource,
    };

    use super::*;
    use crc32fast::Hasher as Crc32;
    use digest::Digest;
    use futures::{channel::oneshot::channel, TryStreamExt};
    use md5::Md5;
    use serde_json::json;
    use std::{
        boxed::Box,
        io::Read,
        sync::{
            atomic::{AtomicUsize, Ordering::Relaxed},
            Arc,
        },
    };
    use tokio::task::{spawn, spawn_blocking};
    use warp::{
        filters::{body::json as json_as_body, multipart::form as form_as_body},
        header,
        http::{HeaderValue, StatusCode},
        multipart::{FormData, Part},
        path,
        reply::{json as reply_json, Response},
        Buf, Filter, Rejection,
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
    async fn test_form_upload() -> anyhow::Result<()> {
        env_logger::try_init().ok();

        const FILE_CONTENT: &[u8] = b"01234567890";

        let routes = warp::path::end()
            .and(form_as_body())
            .and_then(|form_data: FormData| async {
                let mut form_data: HashMap<String, Part> = form_data
                    .try_collect::<Vec<_>>()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|part| (part.name().to_owned(), part))
                    .collect::<HashMap<String, Part>>();
                assert_eq!(form_data.len(), 4);
                let mut key_buf = String::new();
                form_data
                    .get_mut("key")
                    .unwrap()
                    .data()
                    .await
                    .unwrap()
                    .unwrap()
                    .reader()
                    .read_to_string(&mut key_buf)
                    .unwrap();
                assert_eq!("testfile".to_owned(), key_buf);
                let mut crc32_buf = String::new();
                form_data
                    .get_mut("crc32")
                    .unwrap()
                    .data()
                    .await
                    .unwrap()
                    .unwrap()
                    .reader()
                    .read_to_string(&mut crc32_buf)
                    .unwrap();
                let crc32 = {
                    let mut hasher = Crc32::new();
                    hasher.update(FILE_CONTENT);
                    hasher.finalize()
                };
                assert_eq!(crc32.to_string(), crc32_buf);
                let file = form_data.get_mut("file").unwrap();
                assert_eq!(file.filename(), Some("testfilename"));
                assert_eq!(file.content_type(), Some("text/plain"));
                let mut file_data_buf = Vec::new();
                file.data()
                    .await
                    .unwrap()
                    .unwrap()
                    .reader()
                    .read_to_end(&mut file_data_buf)
                    .unwrap();
                assert_eq!(FILE_CONTENT.to_vec(), file_data_buf);
                assert!(form_data.get("token").is_some());
                Ok::<_, Rejection>(reply_json(&json!({ "key": "testfile" })))
            });
        starts_with_server!(addr, routes, {
            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 1,
            };
            spawn_blocking::<_, HttpCallResult<_>>(move || {
                let response = caller.form_upload(&FormUploadRequest::new(
                    Some("testfile"),
                    Some("testfilename"),
                    Some("text/plain"),
                    UploadSource::Data(Arc::new(FILE_CONTENT.to_vec())),
                    None,
                    None,
                ))?;
                assert_eq!(
                    response.response_body.get("key").and_then(|s| s.as_str()),
                    Some("testfile"),
                );
                Ok(())
            })
            .await??;
        });
        Ok(())
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
                        serde_json::to_vec(&json!({ "uploadId": "fakeuploadid" }))
                            .unwrap()
                            .into(),
                    )
                },
            );
        starts_with_server!(addr, routes, {
            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 1,
            };
            spawn_blocking::<_, HttpCallResult<_>>(move || {
                let response =
                    caller.init_parts(&InitPartsRequest::new("test-bucket", Some("test-key")))?;
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
            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 3,
            };
            {
                let called_times = called_times.to_owned();
                spawn_blocking::<_, HttpCallResult<_>>(move || {
                    let err = caller
                        .init_parts(&InitPartsRequest::new("test-bucket", None))
                        .unwrap_err();
                    match err {
                        HttpCallError::StatusCodeError(err) => {
                            assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
                            assert_eq!(err.error_message(), Some("bad token"));
                        }
                        _ => unreachable!(),
                    }
                    assert_eq!(called_times.load(Relaxed), 3);
                    Ok(())
                })
                .await??;
            }
            called_times.store(0, Relaxed);

            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)])
                    .should_punish_callback(Box::new(|err| match err {
                        HttpCallError::ReqwestError(err) if err.is_builder() => false,
                        HttpCallError::StatusCodeError(err) => !err.status_code().is_client_error(),
                        _ => true,
                    }))
                    .build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 3,
            };
            spawn_blocking::<_, HttpCallResult<_>>(move || {
                let err = caller
                    .init_parts(&InitPartsRequest::new("test-bucket", None))
                    .unwrap_err();
                match err {
                    HttpCallError::StatusCodeError(err) => {
                        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
                        assert_eq!(err.error_message(), Some("bad token"));
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
            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 1,
            };
            spawn_blocking::<_, HttpCallResult<_>>(move || {
                let response = caller.upload_part(&UploadPartRequest {
                    bucket_name: "test-bucket",
                    object_name: Some("test-key"),
                    upload_id: "fakeuploadid",
                    part_number: 1,
                    part_reader: PartReader::new(
                        UploadSource::Data(Arc::new(PART_CONTENT.to_vec())),
                        0,
                        1 << 20,
                    ),
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
            let caller = UploadApiCaller {
                up_selector: HostSelectorBuilder::new(vec![format!("http://{}", addr)]).build(),
                upload_token_provider: Box::new(BucketUploadTokenProvider::new(
                    "test-bucket",
                    Duration::from_secs(60),
                    Box::new(get_credential()),
                )),
                tries: 1,
            };
            spawn_blocking::<_, HttpCallResult<_>>(move || {
                let response = caller.complete_parts(&CompletePartsRequest {
                    bucket_name: "test-bucket",
                    object_name: Some("~"),
                    upload_id: "fakeuploadid",
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
