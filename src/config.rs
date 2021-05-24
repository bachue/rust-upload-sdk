use crate::UploaderBuilder;
use log::{error, info, warn};
use notify::{watcher, DebouncedEvent, RecursiveMode, Result as NotifyResult, Watcher};
use once_cell::sync::{Lazy, OnceCell};
use reqwest::blocking::Client as HTTPClient;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryInto,
    env, fmt, fs,
    path::{Path, PathBuf},
    sync::{mpsc::channel, RwLock},
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};
use tap::prelude::*;

/// 七牛配置信息
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Config {
    #[serde(alias = "ak")]
    access_key: String,
    #[serde(alias = "sk")]
    secret_key: String,

    bucket: String,

    #[serde(alias = "up_hosts")]
    up_urls: Option<Vec<String>>,

    #[serde(alias = "uc_hosts")]
    uc_urls: Option<Vec<String>>,

    #[serde(alias = "part")]
    part_size: Option<u64>,

    retry: Option<usize>,
    punish_time_s: Option<u64>,
    base_timeout_ms: Option<u64>,
    base_timeout_multiple_percents: Option<HashMap<String, u32>>,
    dial_timeout_ms: Option<u64>,
}

static QINIU_CONFIG: Lazy<RwLock<Option<Config>>> = Lazy::new(|| {
    RwLock::new(load_config()).tap(|_| {
        on_config_updated(|| {
            if let Some(config) = load_config() {
                *QINIU_CONFIG.write().unwrap() = Some(config);
            }
            info!("QINIU_CONFIG reloaded: {:?}", QINIU_CONFIG);
        })
    })
});
pub(super) static HTTP_CLIENT: Lazy<RwLock<HTTPClient>> = Lazy::new(|| {
    RwLock::new(build_http_client()).tap(|_| {
        on_config_updated(|| {
            *HTTP_CLIENT.write().unwrap() = build_http_client();
            info!("HTTP_CLIENT reloaded: {:?}", HTTP_CLIENT);
        })
    })
});

/// 判断当前是否已经启用七牛环境
///
/// 如果当前没有设置 QINIU 环境变量，或加载该环境变量出现错误，则返回 false
#[inline]
pub fn is_qiniu_enabled() -> bool {
    QINIU_CONFIG.read().unwrap().is_some()
}

fn build_http_client() -> HTTPClient {
    let mut base_timeout_ms = 30000u64;
    let mut dial_timeout_ms = 500u64;
    if let Some(config) = QINIU_CONFIG.read().unwrap().as_ref() {
        if let Some(value) = config.base_timeout_ms {
            if value > 0 {
                base_timeout_ms = value;
            }
        }
        if let Some(value) = config.dial_timeout_ms {
            if value > 0 {
                dial_timeout_ms = value;
            }
        }
    }
    let user_agent = format!("QiniuRustUpload/{}", env!("CARGO_PKG_VERSION"));
    HTTPClient::builder()
        .user_agent(user_agent)
        .connect_timeout(Duration::from_millis(dial_timeout_ms))
        .timeout(Duration::from_millis(base_timeout_ms))
        .pool_max_idle_per_host(5)
        .connection_verbose(true)
        .build()
        .expect("Failed to build Reqwest Client")
}

const QINIU_ENV: &str = "QINIU";

fn load_config() -> Option<Config> {
    if let Ok(qiniu_config_path) = env::var(QINIU_ENV) {
        if let Ok(qiniu_config) = fs::read(&qiniu_config_path) {
            let qiniu_config: Option<Config> = if qiniu_config_path.ends_with(".toml") {
                toml::from_slice(&qiniu_config).ok()
            } else {
                serde_json::from_slice(&qiniu_config).ok()
            };
            if let Some(qiniu_config) = qiniu_config {
                setup_config_watcher(&qiniu_config_path);
                return Some(qiniu_config);
            } else {
                error!(
                    "Qiniu config file cannot be deserialized: {}",
                    qiniu_config_path
                );
                return None;
            }
        } else {
            error!("Qiniu config file cannot be open: {}", qiniu_config_path);
            return None;
        }
    } else {
        warn!("QINIU Env IS NOT ENABLED");
        return None;
    }

    fn setup_config_watcher(config_path: impl Into<PathBuf>) {
        let config_path = config_path.into();
        static UNIQUE_THREAD: OnceCell<JoinHandle<()>> = OnceCell::new();

        if let Err(err) = UNIQUE_THREAD.get_or_try_init(|| {
            ThreadBuilder::new()
                .name("qiniu-config-watcher".into())
                .spawn(move || {
                    if let Err(err) = setup_config_watcher_inner(&config_path) {
                        error!("Qiniu config file watcher was setup failed: {:?}", err);
                    }
                })
        }) {
            error!(
                "Failed to start thread to watch Qiniu config file: {:?}",
                err
            );
        }

        fn setup_config_watcher_inner(config_path: &Path) -> NotifyResult<()> {
            let (tx, rx) = channel();
            let mut watcher = watcher(tx, Duration::from_millis(500))?;
            watcher.watch(config_path, RecursiveMode::NonRecursive)?;

            info!("Qiniu config file watcher was setup");

            loop {
                match rx.recv() {
                    Ok(event) => match event {
                        DebouncedEvent::Create(_) | DebouncedEvent::Write(_) => {
                            info!("Received event {:?} from Qiniu config file watcher", event);
                            for handle in CONFIG_UPDATE_HANDLERS.read().unwrap().iter() {
                                handle();
                            }
                        }
                        DebouncedEvent::Error(err, _) => {
                            error!(
                                "Received error event from Qiniu config file watcher: {:?}",
                                err
                            );
                        }
                        _ => {}
                    },
                    Err(err) => {
                        error!(
                            "Failed to receive event from Qiniu config file watcher: {:?}",
                            err
                        );
                    }
                }
            }
        }
    }
}

type ConfigUpdateHandler = fn();
type ConfigUpdateHandlers = Vec<ConfigUpdateHandler>;
static CONFIG_UPDATE_HANDLERS: Lazy<RwLock<ConfigUpdateHandlers>> = Lazy::new(Default::default);

pub(super) fn on_config_updated(handle: fn()) {
    CONFIG_UPDATE_HANDLERS.write().unwrap().push(handle);
}

impl Config {
    /// 创建七牛配置信息构建器
    pub fn builder(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        bucket: impl Into<String>,
    ) -> ConfigBuilder {
        ConfigBuilder::new(access_key, secret_key, bucket)
    }
}

/// 七牛配置信息构建器
#[derive(Debug)]
pub struct ConfigBuilder {
    inner: Config,
}

impl ConfigBuilder {
    /// 创建七牛配置信息构建器
    #[inline]
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        Self {
            inner: Config {
                access_key: access_key.into(),
                secret_key: secret_key.into(),
                bucket: bucket.into(),
                up_urls: None,
                uc_urls: None,
                part_size: None,
                retry: None,
                punish_time_s: None,
                base_timeout_ms: None,
                base_timeout_multiple_percents: None,
                dial_timeout_ms: None,
            },
        }
    }

    /// 构建七牛配置信息
    #[inline]
    pub fn build(self) -> Config {
        self.inner
    }

    /// 配置 UP 服务器域名列表
    #[inline]
    pub fn up_urls(mut self, up_urls: Vec<String>) -> Self {
        self.inner.up_urls = Some(up_urls);
        self
    }

    /// 配置 UC 服务器域名列表
    #[inline]
    pub fn uc_urls(mut self, uc_urls: Vec<String>) -> Self {
        self.inner.uc_urls = Some(uc_urls);
        self
    }

    /// 配置默认上传分片大小，单位为 MB，默认为 4 MB
    #[inline]
    pub fn part_size(mut self, part_size: u64) -> Self {
        self.inner.part_size = Some(part_size);
        self
    }

    /// 配置 UP 和 UC 服务器访问重试次数，默认为 10
    #[inline]
    pub fn retry(mut self, retry: usize) -> Self {
        self.inner.retry = Some(retry);
        self
    }

    /// 配置域名访问失败后的惩罚时长，默认为 30 分钟
    #[inline]
    pub fn punish_time_s(mut self, punish_duration: Duration) -> Self {
        self.inner.punish_time_s = Some(punish_duration.as_millis().try_into().unwrap_or(u64::MAX));
        self
    }

    /// 配置域名访问的基础超时时长，默认为 30 秒
    #[inline]
    pub fn base_timeout_ms(mut self, base_timeout_duration: Duration) -> Self {
        self.inner.base_timeout_ms = Some(
            base_timeout_duration
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        self
    }

    /// 配置域名访问的基础超时时长倍数百分比，service_name 指的是服务名称，percent 指的是倍数百分比，最终服务的基础超时时长为 base_timeout_ms * 该服务对应的 percent / 100
    #[inline]
    pub fn add_base_timeout_multiple_percent(
        mut self,
        service_name: ServiceName,
        percent: u32,
    ) -> Self {
        if let Some(percents) = &mut self.inner.base_timeout_multiple_percents {
            percents.insert(service_name.to_string(), percent);
        } else {
            let mut percents = HashMap::new();
            percents.insert(service_name.to_string(), percent);
            self.inner.base_timeout_multiple_percents = Some(percents);
        }
        self
    }

    /// 配置域名连接的超时时长，默认为 500 毫秒
    #[inline]
    pub fn dial_timeout_ms(mut self, dial_timeout_duration: Duration) -> Self {
        self.inner.dial_timeout_ms = Some(
            dial_timeout_duration
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        self
    }
}

#[inline]
pub(super) fn build_uploader_builder_from_env() -> Option<UploaderBuilder> {
    QINIU_CONFIG
        .read()
        .unwrap()
        .as_ref()
        .map(build_uploader_builder_from_config)
}

fn build_uploader_builder_from_config(config: &Config) -> UploaderBuilder {
    let mut builder = UploaderBuilder::new(&config.access_key, &config.secret_key, &config.bucket);
    if let Some(up_urls) = config.up_urls.as_ref() {
        builder = builder.up_urls(up_urls.to_owned());
    }
    if let Some(uc_urls) = config.uc_urls.as_ref() {
        builder = builder.uc_urls(uc_urls.to_owned());
    }
    if let Some(retry) = config.retry.as_ref() {
        builder = builder
            .up_tries(retry.to_owned())
            .uc_tries(retry.to_owned());
    }
    if let Some(base_timeout_multiple_percents) = config.base_timeout_multiple_percents.as_ref() {
        if let Some(&uc_timeout_multiple_percents) =
            base_timeout_multiple_percents.get(&ServiceName::Uc.to_string())
        {
            builder = builder.uc_timeout_multiple(uc_timeout_multiple_percents);
        }
        if let Some(&up_timeout_multiple_percents) =
            base_timeout_multiple_percents.get(&ServiceName::Up.to_string())
        {
            builder = builder.up_timeout_multiple(up_timeout_multiple_percents);
        }
    }

    if let Some(punish_time_s) = config.punish_time_s.as_ref() {
        builder = builder.punish_duration(Duration::from_secs(punish_time_s.to_owned()));
    }
    if let Some(base_timeout_ms) = config.base_timeout_ms.as_ref() {
        builder = builder.base_timeout(Duration::from_millis(base_timeout_ms.to_owned()));
    }
    if let Some(part_size) = config.part_size.as_ref() {
        builder = builder.part_size(part_size.to_owned() * (1 << 20));
    }
    builder
}

/// 服务名称
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServiceName {
    /// UP 服务器
    Up,
    /// UC 服务器
    Uc,
}

impl fmt::Display for ServiceName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uc => "uc".fmt(f),
            Self::Up => "up".fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        error::Error,
        fs::{remove_file, OpenOptions},
        io::Write,
        sync::atomic::{AtomicUsize, Ordering::Relaxed},
        thread::sleep,
    };
    use tempfile::Builder as TempFileBuilder;

    #[test]
    fn test_load_config() -> Result<(), Box<dyn Error>> {
        env_logger::try_init().ok();

        let mut config = Config {
            access_key: "test-ak-1".into(),
            secret_key: "test-sk-1".into(),
            bucket: "test-bucket-1".into(),
            up_urls: Some(vec!["http://up1.com".into(), "http://up2.com".into()]),
            uc_urls: Default::default(),
            retry: Default::default(),
            punish_time_s: Default::default(),
            base_timeout_ms: Default::default(),
            dial_timeout_ms: Default::default(),
            part_size: Default::default(),
            base_timeout_multiple_percents: Default::default(),
        };
        let tempfile_path = {
            let mut tempfile = TempFileBuilder::new().suffix(".toml").tempfile()?;
            tempfile.write_all(&toml::to_vec(&config)?)?;
            tempfile.flush()?;
            env::set_var(QINIU_ENV, tempfile.path().as_os_str());
            tempfile.into_temp_path()
        };

        static UPDATED: AtomicUsize = AtomicUsize::new(0);
        UPDATED.store(0, Relaxed);

        let loaded = load_config().unwrap();
        assert_eq!(loaded, config);

        on_config_updated(|| {
            UPDATED.fetch_add(1, Relaxed);
        });
        on_config_updated(|| {
            UPDATED.fetch_add(1, Relaxed);
        });
        on_config_updated(|| {
            UPDATED.fetch_add(1, Relaxed);
        });

        sleep(Duration::from_secs(1));

        config.access_key = "test-ak-2".into();
        config.secret_key = "test-sk-2".into();
        config.bucket = "test-bucket-2".into();

        {
            let mut tempfile = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&tempfile_path)?;
            tempfile.write_all(&toml::to_vec(&config)?)?;
            tempfile.flush()?;
        }

        sleep(Duration::from_secs(1));
        assert_eq!(UPDATED.load(Relaxed), 3);

        remove_file(tempfile_path)?;

        Ok(())
    }
}
