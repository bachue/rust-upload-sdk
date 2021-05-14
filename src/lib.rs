#![warn(missing_docs)]
#![allow(dead_code)]

//! # qiniu-download
//!
//! ## 七牛上传 SDK
//!
//! 负责上传七牛对象

mod config;
mod host_selector;
mod query;
mod upload_policy;

use config::HTTP_CLIENT;
