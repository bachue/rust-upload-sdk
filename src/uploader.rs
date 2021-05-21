use crate::{
    config::{build_uploader_builder_from_env, on_config_updated},
    credential::{CredentialProvider, StaticCredentialProvider},
    error::{HttpCallError, HttpCallResult},
    host_selector::HostSelector,
    query::HostsQuerier,
    upload_apis::{
        CompletePartInfo, CompletePartsRequest, CompletePartsRequestBody, FormUploadRequest,
        InitPartsRequest, UploadApiCaller, UploadPartRequest,
    },
    upload_token::BucketUploadTokenProvider,
    utils::UploadSource,
};
use log::info;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde_json::Value as JSONValue;
use std::{
    collections::HashMap,
    fs::File,
    io::Result as IOResult,
    mem::take,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};
use tap::Tap;

/// 对象上传器
#[derive(Debug, Clone)]
pub struct Uploader {
    inner: Arc<UploaderInner>,
}

#[derive(Debug)]
struct UploaderInner {
    api_caller: UploadApiCaller,
    bucket_name: String,
    part_size: u64,
}

/// 对象上传构建器
#[derive(Debug)]
pub struct UploaderBuilder {
    credential: Box<dyn CredentialProvider>,
    access_key: String,
    bucket: String,
    up_urls: Vec<String>,
    uc_urls: Vec<String>,
    up_tries: usize,
    uc_tries: usize,
    part_size: u64,
    use_https: bool,
    update_interval: Duration,
    punish_duration: Duration,
    base_timeout: Duration,
    max_punished_times: usize,
    max_punished_hosts_percent: u8,
}

impl UploaderBuilder {
    /// 新建上传构建器
    #[inline]
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        let access_key = access_key.into();
        Self {
            credential: Box::new(StaticCredentialProvider::new(
                access_key.to_owned(),
                secret_key.into(),
            )),
            bucket: bucket.into(),
            access_key,
            up_urls: Default::default(),
            uc_urls: Default::default(),
            up_tries: 10,
            uc_tries: 10,
            part_size: 1 << 22,
            use_https: false,
            update_interval: Duration::from_secs(60),
            punish_duration: Duration::from_secs(30 * 60),
            base_timeout: Duration::from_secs(30),
            max_punished_times: 5,
            max_punished_hosts_percent: 50,
        }
    }

    /// 设置七牛 UP 服务器 URL 列表
    #[inline]
    pub fn up_urls(mut self, up_urls: Vec<String>) -> Self {
        self.up_urls = up_urls;
        self
    }

    /// 设置七牛 UC 服务器 URL 列表
    #[inline]
    pub fn uc_urls(mut self, uc_urls: Vec<String>) -> Self {
        self.uc_urls = uc_urls;
        self
    }

    /// 设置对象上传最大尝试次数
    #[inline]
    pub fn up_tries(mut self, up_tries: usize) -> Self {
        self.up_tries = up_tries;
        self
    }

    /// 设置 UC 查询的最大尝试次数
    #[inline]
    pub fn uc_tries(mut self, uc_tries: usize) -> Self {
        self.uc_tries = uc_tries;
        self
    }

    /// 设置是否使用 HTTPS 协议来访问 UP / UC 服务器
    #[inline]
    pub fn use_https(mut self, use_https: bool) -> Self {
        self.use_https = use_https;
        self
    }

    /// 设置 UC 查询的频率
    #[inline]
    pub fn update_interval(mut self, update_interval: Duration) -> Self {
        self.update_interval = update_interval;
        self
    }

    /// 设置域名访问失败后的惩罚时长
    #[inline]
    pub fn punish_duration(mut self, punish_duration: Duration) -> Self {
        self.punish_duration = punish_duration;
        self
    }

    /// 设置域名访问的基础超时时长
    #[inline]
    pub fn base_timeout(mut self, base_timeout: Duration) -> Self {
        self.base_timeout = base_timeout;
        self
    }

    /// 配置默认上传分片大小，单位为字节
    #[inline]
    pub fn part_size(mut self, part_size: u64) -> Self {
        self.part_size = part_size;
        self
    }

    /// 设置失败域名的最大重试次数
    ///
    /// 一旦一个域名的被惩罚次数超过限制，则域名选择器不会选择该域名，除非被惩罚的域名比例超过上限，或惩罚时长超过指定时长
    #[inline]
    pub fn max_punished_times(mut self, max_punished_times: usize) -> Self {
        self.max_punished_times = max_punished_times;
        self
    }

    /// 设置被惩罚的域名最大比例
    ///
    /// 域名选择器在搜索域名时，一旦被跳过的域名比例大于该值，则下一个域名将被选中，不管该域名是否也被惩罚。一旦该域名成功，则惩罚将立刻被取消
    #[inline]
    pub fn max_punished_hosts_percent(mut self, max_punished_hosts_percent: u8) -> Self {
        self.max_punished_hosts_percent = max_punished_hosts_percent;
        self
    }

    /// 构建对象上传器
    #[inline]
    pub fn build(self) -> Uploader {
        let up_querier = if self.uc_urls.is_empty() {
            None
        } else {
            Some(HostsQuerier::new(
                HostSelector::builder(self.uc_urls)
                    .update_interval(self.update_interval)
                    .punish_duration(self.punish_duration)
                    .max_punished_times(self.max_punished_times)
                    .max_punished_hosts_percent(self.max_punished_hosts_percent)
                    .base_timeout(self.base_timeout)
                    .build(),
                self.uc_tries,
            ))
        };
        let up_selector = {
            let access_key = self.access_key;
            let bucket = self.bucket.to_owned();
            let use_https = self.use_https;
            HostSelector::builder(self.up_urls)
                .update_callback(Box::new(move || {
                    if let Some(up_querier) = &up_querier {
                        up_querier.query_for_up_urls(&access_key, &bucket, use_https)
                    } else {
                        Ok(vec![])
                    }
                }))
                .should_punish_callback(Box::new(|err| match err {
                    HttpCallError::ReqwestError(err) if err.is_builder() => false,
                    HttpCallError::StatusCodeError(err) => {
                        !is_client_error_status(err.status_code())
                    }
                    _ => true,
                }))
                .update_interval(self.update_interval)
                .punish_duration(self.punish_duration)
                .max_punished_times(self.max_punished_times)
                .max_punished_hosts_percent(self.max_punished_hosts_percent)
                .base_timeout(self.base_timeout)
                .build()
        };

        Uploader {
            inner: Arc::new(UploaderInner {
                api_caller: UploadApiCaller::new(
                    up_selector,
                    Box::new(BucketUploadTokenProvider::new(
                        self.bucket.to_owned(),
                        self.base_timeout,
                        self.credential,
                    )),
                    self.up_tries,
                ),
                bucket_name: self.bucket,
                part_size: self.part_size,
            }),
        }
    }

    /// 从环境变量创建对象上传构建器
    #[inline]
    pub fn from_env() -> Option<Self> {
        build_uploader_builder_from_env()
    }
}

impl Uploader {
    #[inline]
    /// 从环境变量创建对象上传器
    pub fn from_env() -> Option<Self> {
        static UPLOADER: Lazy<RwLock<Option<Uploader>>> = Lazy::new(|| {
            RwLock::new(build_uploader()).tap(|_| {
                on_config_updated(|| {
                    *UPLOADER.write().unwrap() = build_uploader();
                    info!("UPLOADER reloaded: {:?}", UPLOADER);
                })
            })
        });
        return UPLOADER.read().unwrap().as_ref().map(|u| u.to_owned());

        #[inline]
        fn build_uploader() -> Option<Uploader> {
            UploaderBuilder::from_env().map(|b| b.build())
        }
    }

    /// 创建上传文件请求构建器
    #[inline]
    pub fn upload_file(&self, file: File) -> UploadRequestBuilder {
        UploadRequestBuilder {
            uploader: self,
            source: UploadSource::File(Arc::new(file)),
            object_name: None,
            upload_progress_callback: None,
            file_name: None,
            mime_type: None,
            metadata: None,
            custom_vars: None,
        }
    }

    /// 创建上传文件请求构建器
    #[inline]
    pub fn upload_path(&self, path: impl AsRef<Path>) -> IOResult<UploadRequestBuilder> {
        let file = File::open(path.as_ref())?;
        Ok(self.upload_file(file))
    }
}

/// 上传文件请求构建器
pub struct UploadRequestBuilder<'a> {
    uploader: &'a Uploader,
    source: UploadSource,
    object_name: Option<String>,
    file_name: Option<String>,
    mime_type: Option<String>,
    metadata: Option<HashMap<String, String>>,
    custom_vars: Option<HashMap<String, String>>,
    upload_progress_callback: Option<Box<dyn Fn(&UploadProgressInfo) -> HttpCallResult<()>>>,
}

impl<'a> UploadRequestBuilder<'a> {
    /// 设置对象名称
    #[inline]
    pub fn object_name(mut self, object_name: impl Into<String>) -> Self {
        self.object_name = Some(object_name.into());
        self
    }

    /// 设置原始文件名
    #[inline]
    pub fn file_name(mut self, file_name: impl Into<String>) -> Self {
        self.file_name = Some(file_name.into());
        self
    }

    /// 设置文件 MIME 类型
    #[inline]
    pub fn mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    /// 追加自定义元数据
    pub fn add_metadata(
        mut self,
        metadata_key: impl Into<String>,
        metadata_value: impl Into<String>,
    ) -> Self {
        if let Some(metadata) = &mut self.metadata {
            metadata.insert(metadata_key.into(), metadata_value.into());
        } else {
            let mut metadata = HashMap::new();
            metadata.insert(metadata_key.into(), metadata_value.into());
            self.metadata = Some(metadata);
        }
        self
    }

    /// 设置自定义元数据
    #[inline]
    pub fn metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// 追加自定义变量
    pub fn add_custom_var(
        mut self,
        custom_var_name: impl Into<String>,
        custom_var_value: impl Into<String>,
    ) -> Self {
        if let Some(custom_vars) = &mut self.custom_vars {
            custom_vars.insert(custom_var_name.into(), custom_var_value.into());
        } else {
            let mut custom_vars = HashMap::new();
            custom_vars.insert(custom_var_name.into(), custom_var_value.into());
            self.custom_vars = Some(custom_vars);
        }
        self
    }

    /// 设置自定义变量
    #[inline]
    pub fn custom_vars(mut self, custom_vars: HashMap<String, String>) -> Self {
        self.custom_vars = Some(custom_vars);
        self
    }

    /// 设置上传进度回调函数（仅在分片上传时生效）
    #[inline]
    pub fn upload_progress_callback(
        mut self,
        upload_progress_callback: Box<dyn Fn(&UploadProgressInfo) -> HttpCallResult<()>>,
    ) -> Self {
        self.upload_progress_callback = Some(upload_progress_callback);
        self
    }

    /// 开始上传
    #[inline]
    pub fn start(self) -> HttpCallResult<UploadResult> {
        if self.source.len()? <= self.uploader.inner.part_size {
            self.start_form_upload()
        } else {
            self.start_resumable_upload()
        }
    }

    fn start_form_upload(self) -> HttpCallResult<UploadResult> {
        let mut form_upload_result =
            self.uploader
                .inner
                .api_caller
                .form_upload(&FormUploadRequest::new(
                    self.object_name.as_deref(),
                    self.file_name.as_deref(),
                    self.mime_type.as_deref(),
                    self.source,
                    self.metadata,
                    self.custom_vars,
                ))?;
        Ok(UploadResult {
            response_body: take(form_upload_result.response_body_mut()),
        })
    }

    fn start_resumable_upload(self) -> HttpCallResult<UploadResult> {
        let init_parts_response =
            self.uploader
                .inner
                .api_caller
                .init_parts(&InitPartsRequest::new(
                    self.uploader.inner.bucket_name.as_ref(),
                    self.object_name.as_deref(),
                ))?;
        let mut partitioner = self.source.part(self.uploader.inner.part_size);
        let mut part_number = 1u32;
        let mut uploaded = 0u64;
        let mut completed_parts = Vec::new();
        while let Some(part_reader) = partitioner.next_part_reader()? {
            let mut upload_result =
                self.uploader
                    .inner
                    .api_caller
                    .upload_part(&UploadPartRequest::new(
                        self.uploader.inner.bucket_name.as_ref(),
                        self.object_name.as_deref(),
                        init_parts_response.response_body().upload_id(),
                        part_number,
                        part_reader,
                    ))?;
            uploaded = uploaded.saturating_add(upload_result.uploaded());
            if let Some(upload_progress_callback) = &self.upload_progress_callback {
                upload_progress_callback(&UploadProgressInfo {
                    upload_id: init_parts_response.response_body().upload_id(),
                    uploaded,
                    part_number,
                })?;
            }
            completed_parts.push(CompletePartInfo::new(
                take(upload_result.response_body_mut().etag_mut()),
                part_number,
            ));
            part_number = part_number.saturating_add(1);
        }
        let mut complete_parts_result =
            self.uploader
                .inner
                .api_caller
                .complete_parts(&CompletePartsRequest::new(
                    self.uploader.inner.bucket_name.as_ref(),
                    self.object_name.as_deref(),
                    init_parts_response.response_body().upload_id(),
                    CompletePartsRequestBody::new(
                        completed_parts,
                        self.file_name,
                        self.mime_type,
                        self.metadata,
                        self.custom_vars,
                    ),
                ))?;
        Ok(UploadResult {
            response_body: take(complete_parts_result.response_body_mut()),
        })
    }
}

/// 上传结果
#[derive(Debug, Clone)]
pub struct UploadResult {
    response_body: JSONValue,
}

impl UploadResult {
    /// 获取上传结果响应
    #[inline]
    pub fn response_body(&self) -> &JSONValue {
        &self.response_body
    }
}

/// 上传进度信息
#[derive(Debug, Clone)]
pub struct UploadProgressInfo<'a> {
    upload_id: &'a str,
    uploaded: u64,
    part_number: u32,
}

impl<'a> UploadProgressInfo<'a> {
    /// 获取 Upload ID
    #[inline]
    pub fn upload_id(&self) -> &str {
        self.upload_id
    }

    /// 获取已经上传的数据量
    #[inline]
    pub fn uploaded(&self) -> u64 {
        self.uploaded
    }

    /// 获取上传成功的分片号码
    #[inline]
    pub fn part_number(&self) -> u32 {
        self.part_number
    }
}

#[inline]
fn is_client_error_status(code: StatusCode) -> bool {
    return code.is_client_error() && code != to_status_code(406)
        || [
            to_status_code(501),
            to_status_code(573),
            to_status_code(608),
            to_status_code(612),
            to_status_code(614),
            to_status_code(616),
            to_status_code(619),
            to_status_code(630),
            to_status_code(631),
            to_status_code(640),
            to_status_code(701),
        ]
        .contains(&code);

    #[inline]
    fn to_status_code(code: u16) -> StatusCode {
        StatusCode::from_u16(code).expect("Invalid status code")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use md5::Md5;
    use rand::{prelude::*, rngs::OsRng};
    use reqwest::blocking::get;
    use std::{
        env,
        io::{copy, Read, Seek, SeekFrom},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tempfile::tempfile;

    #[test]
    fn test_upload_files() -> anyhow::Result<()> {
        env_logger::try_init().ok();

        let access_key = env::var("QINIU_ACCESS_KEY")?;
        let secret_key = env::var("QINIU_SECRET_KEY")?;
        let bucket_name = env::var("QINIU_BUCKET_NAME")?;
        let bucket_domain = env::var("QINIU_BUCKET_DOMAIN")?;
        let uc_url = env::var("QINIU_UC_URL")?;

        let uploader = UploaderBuilder::new(access_key, secret_key, bucket_name)
            .uc_urls(vec![uc_url])
            .build();

        test_upload_file_of(&uploader, &bucket_domain, 1023)?;
        test_upload_file_of(&uploader, &bucket_domain, 1025)?;
        test_upload_file_of(&uploader, &bucket_domain, (1 << 20) * 3)?;
        test_upload_file_of(&uploader, &bucket_domain, (1 << 20) * 4)?;
        test_upload_file_of(&uploader, &bucket_domain, (1 << 20) * 4 + 2)?;
        test_upload_file_of(&uploader, &bucket_domain, (1 << 20) * 9 - 2)?;
        return Ok(());

        fn test_upload_file_of(
            uploader: &Uploader,
            bucket_domain: &str,
            size: u64,
        ) -> anyhow::Result<()> {
            let (file, md5) = {
                let mut file = tempfile()?;
                let rng = Box::new(OsRng) as Box<dyn RngCore>;
                copy(&mut rng.take(size), &mut file)?;
                file.seek(SeekFrom::Start(0))?;

                let mut hasher = Md5::new();
                copy(&mut file, &mut hasher)?;
                file.seek(SeekFrom::Start(0))?;

                (file, hasher.finalize())
            };
            let result = uploader
                .upload_file(file)
                .object_name(format!(
                    "upload-{}-{}",
                    size,
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
                ))
                .start()?;
            let key = result
                .response_body()
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap();
            let url = format!("http://{}/{}", bucket_domain, key);
            let mut response = get(&url)?;
            let returned_md5 = {
                let mut hasher = Md5::new();
                copy(&mut response, &mut hasher)?;
                hasher.finalize()
            };
            assert_eq!(md5, returned_md5);
            Ok(())
        }
    }
}
