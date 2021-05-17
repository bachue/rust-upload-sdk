use reqwest::{
    blocking::Response,
    header::{HeaderName, HeaderValue},
    Error as ReqwestError, StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Error as JSONError;
use std::io::Error as IOError;
use thiserror::Error;
use url::ParseError as URLParseError;

#[derive(Error, Debug)]
#[non_exhaustive]
pub(super) enum HTTPCallError {
    #[error("IO error: {0}")]
    IOError(#[from] IOError),
    #[error("Invalid URL error: {0}")]
    InvalidURL(#[from] URLParseError),
    #[error("HTTP Call error: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("JSON decode error: {error:?}, status_code: {status_code:?}, req_id: {request_id:?}")]
    JSONDecodeError {
        error: JSONError,
        status_code: StatusCode,
        request_id: Option<HeaderValue>,
    },
    #[error(
        "HTTP Status Code error: {status_code:?}, message: {error_message:?}, req_id: {request_id:?}"
    )]
    StatusCodeError {
        status_code: StatusCode,
        error_message: Option<Box<str>>,
        request_id: Option<HeaderValue>,
    },
}
pub(super) type HTTPCallResult<T> = Result<T, HTTPCallError>;

const X_REQ_ID: &str = "x-reqid";

impl From<Response> for HTTPCallError {
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
            Ok(error_body) => Self::StatusCodeError {
                status_code,
                request_id,
                error_message: error_body.error,
            },
            Err(error) => Self::JSONDecodeError {
                status_code,
                request_id,
                error,
            },
        }
    }
}

pub(super) fn json_decode_response<T: DeserializeOwned>(response: Response) -> HTTPCallResult<T> {
    let status_code = response.status();
    let request_id = response
        .headers()
        .get(HeaderName::from_static(X_REQ_ID))
        .cloned();
    match serde_json::from_reader::<_, T>(response) {
        Ok(body) => Ok(body),
        Err(error) => Err(HTTPCallError::JSONDecodeError {
            status_code,
            request_id,
            error,
        }),
    }
}
