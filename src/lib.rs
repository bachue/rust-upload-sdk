#![warn(missing_docs)]
#![allow(dead_code)]

//! # qiniu-download
//!
//! ## 七牛上传 SDK
//!
//! 负责上传七牛对象

mod base64;
mod config;
mod credential;
mod host_selector;
mod query;
mod upload_policy;
mod upload_token;

use config::HTTP_CLIENT;
