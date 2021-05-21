use reqwest::{
    blocking::Response,
    header::{HeaderName, HeaderValue},
    Error as ReqwestError, StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Error as JSONError;
use std::{error::Error, fmt, io::Error as IOError};
use thiserror::Error;
use url::ParseError as URLParseError;

/// HTTP 调用错误
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum HttpCallError {
    /// 本地 IO 错误
    #[error("Local IO error: {0}")]
    LocalIoError(#[from] IOError),

    /// 非法的 URL
    #[error("Invalid URL error: {0}")]
    InvalidUrl(#[from] URLParseError),

    /// Reqwest 库调用错误
    #[error("HTTP Call error: {0}")]
    ReqwestError(#[from] ReqwestError),

    /// JSON 解析错误
    #[error("JSON decode error: {0}")]
    JsonDecodeError(#[from] JsonDecodeError),

    /// 状态码错误
    #[error("HTTP Status Code error: {0}")]
    StatusCodeError(#[from] StatusCodeError),
}
/// HTTP 调用结果
pub type HttpCallResult<T> = Result<T, HttpCallError>;

/// JSON 解析错误
#[derive(Debug)]
pub struct JsonDecodeError {
    error: JSONError,
    status_code: StatusCode,
    request_id: Option<HeaderValue>,
}

impl JsonDecodeError {
    pub(super) fn new(
        error: JSONError,
        status_code: StatusCode,
        request_id: Option<HeaderValue>,
    ) -> Self {
        Self {
            error,
            status_code,
            request_id,
        }
    }

    /// 获取核心错误信息
    #[inline]
    pub fn error(&self) -> &JSONError {
        &self.error
    }

    /// 获取错误状态码
    #[inline]
    pub fn status_code(&self) -> StatusCode {
        self.status_code
    }

    /// 获取请求 ID
    #[inline]
    pub fn request_id(&self) -> Option<&HeaderValue> {
        self.request_id.as_ref()
    }
}

impl fmt::Display for JsonDecodeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message: {}, status_code: {}",
            self.error, self.status_code
        )?;
        if let Some(request_id) = &self.request_id {
            write!(f, ", request_id: {:?}", request_id)?;
        }
        Ok(())
    }
}

impl Error for JsonDecodeError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// 状态码错误
#[derive(Debug)]
pub struct StatusCodeError {
    status_code: StatusCode,
    error_message: Option<Box<str>>,
    request_id: Option<HeaderValue>,
}

impl StatusCodeError {
    #[inline]
    pub(super) fn new(
        status_code: StatusCode,
        error_message: Option<Box<str>>,
        request_id: Option<HeaderValue>,
    ) -> Self {
        Self {
            status_code,
            error_message,
            request_id,
        }
    }

    /// 获取错误状态码
    #[inline]
    pub fn status_code(&self) -> StatusCode {
        self.status_code
    }

    /// 获取错误信息
    #[inline]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// 获取请求 ID
    #[inline]
    pub fn request_id(&self) -> Option<&HeaderValue> {
        self.request_id.as_ref()
    }
}

impl fmt::Display for StatusCodeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status_code: {}", self.status_code)?;
        if let Some(error_message) = &self.error_message {
            write!(f, ", error_message: {}", error_message)?;
        }
        if let Some(request_id) = &self.request_id {
            write!(f, ", request_id: {:?}", request_id)?;
        }
        Ok(())
    }
}

impl Error for StatusCodeError {}

const X_REQ_ID: &str = "x-reqid";

impl From<Response> for HttpCallError {
    #[inline]
    fn from(response: Response) -> Self {
        #[derive(Debug, Clone, Deserialize)]
        struct ErrorBody {
            error: Option<Box<str>>,
        }

        let status_code = response.status();
        let request_id = response
            .headers()
            .get(HeaderName::from_static(X_REQ_ID))
            .cloned();

        match serde_json::from_reader::<_, ErrorBody>(response) {
            Ok(error_body) => Self::StatusCodeError(StatusCodeError {
                status_code,
                request_id,
                error_message: error_body.error,
            }),
            Err(error) => Self::JsonDecodeError(JsonDecodeError {
                error,
                status_code,
                request_id,
            }),
        }
    }
}

pub(super) fn json_decode_response<T: DeserializeOwned>(
    response: Response,
) -> HttpCallResult<(T, Option<HeaderValue>)> {
    let status_code = response.status();
    let request_id = response
        .headers()
        .get(HeaderName::from_static(X_REQ_ID))
        .cloned();
    match serde_json::from_reader::<_, T>(response) {
        Ok(body) => Ok((body, request_id)),
        Err(error) => Err(HttpCallError::JsonDecodeError(JsonDecodeError {
            error,
            status_code,
            request_id,
        })),
    }
}
