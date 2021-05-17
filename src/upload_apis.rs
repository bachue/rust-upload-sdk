use crate::{
    config::HTTP_CLIENT,
    credential::StaticCredentialProvider,
    error::{HTTPCallError, HTTPCallResult},
    host_selector::{HostInfo, HostSelector},
};
use reqwest::{blocking::RequestBuilder as HTTPRequestBuilder, Method};
use std::{sync::Arc, thread::sleep, time::Duration};

pub(super) struct UploadAPICaller {
    inner: Arc<UploadAPICallerInner>,
}

struct UploadAPICallerInner {
    up_selector: HostSelector,
    credential_provider: StaticCredentialProvider,
    bucket: String,
    tries: usize,
    part_size: u64,
}

impl UploadAPICaller {
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
        return todo!();

        #[inline]
        fn sleep_before_retry(tries: usize) {
            if tries >= 3 {
                sleep(Duration::from_secs(tries as u64));
            }
        }
    }
}
