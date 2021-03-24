//! Internal traits that define the Isahc configuration system.

use super::{proxy::Proxy, *};
use curl::easy::Easy2;

/// Base trait for any object that can be configured for requests, such as an
/// HTTP request builder or an HTTP client.
#[doc(hidden)]
pub trait WithRequestConfig: Sized {
    /// Invoke a function to mutate the request configuration for this object.
    fn with_config(self, f: impl FnOnce(&mut RequestConfig)) -> Self;
}

/// A helper trait for applying a configuration value to a given curl handle.
pub(crate) trait SetOpt {
    /// Apply this configuration property to the given curl handle.
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error>;
}

// Define this struct inside a macro to reduce some boilerplate.
macro_rules! define_request_config {
    ($($field:ident: $t:ty,)*) => {
        /// Configuration for an HTTP request.
        ///
        /// This struct is not exposed directly, but rather is interacted with
        /// via the [`Configurable`] trait.
        #[derive(Clone, Debug, Default)]
        pub struct RequestConfig {
            $(
                pub(crate) $field: $t,
            )*
        }

        impl RequestConfig {
            pub(crate) fn client_defaults() -> Self {
                Self {
                    // Always start out with latest compatible HTTP version.
                    version_negotiation: Some(VersionNegotiation::default()),
                    // Enable automatic decompression by default for convenience
                    // (and maintain backwards compatibility).
                    automatic_decompression: Some(true),
                    // Erase curl's default auth method of Basic.
                    authentication: Some(Authentication::default()),
                    ..Default::default()
                }
            }

            /// Merge another request configuration into this one. Unspecified
            /// values in this config are replaced with values in the given
            /// config.
            pub(crate) fn merge(&mut self, defaults: &Self) {
                $(
                    if self.$field.is_none() {
                        if let Some(value) = defaults.$field.as_ref() {
                            self.$field = Some(value.clone());
                        }
                    }
                )*
            }
        }
    };
}

define_request_config! {
    // Used by curl
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    expect_100_timeout: Option<Duration>,
    version_negotiation: Option<VersionNegotiation>,
    automatic_decompression: Option<bool>,
    authentication: Option<Authentication>,
    credentials: Option<Credentials>,
    tcp_keepalive: Option<Duration>,
    tcp_nodelay: Option<bool>,
    interface: Option<NetworkInterface>,
    ip_version: Option<IpVersion>,
    dial: Option<Dialer>,
    proxy: Option<Option<http::Uri>>,
    proxy_blacklist: Option<proxy::Blacklist>,
    proxy_authentication: Option<Proxy<Authentication>>,
    proxy_credentials: Option<Proxy<Credentials>>,
    max_upload_speed: Option<u64>,
    max_download_speed: Option<u64>,
    ssl_client_certificate: Option<ClientCertificate>,
    ssl_ca_certificate: Option<CaCertificate>,
    ssl_ciphers: Option<ssl::Ciphers>,
    ssl_options: Option<SslOption>,
    enable_metrics: Option<bool>,

    // Used by interceptors
    redirect_policy: Option<RedirectPolicy>,
    auto_referer: Option<bool>,
    title_case_headers: Option<bool>,
}

impl SetOpt for RequestConfig {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        if let Some(timeout) = self.timeout {
            easy.timeout(timeout)?;
        }

        if let Some(timeout) = self.connect_timeout {
            easy.connect_timeout(timeout)?;
        }

        if let Some(timeout) = self.expect_100_timeout {
            easy.expect_100_timeout(timeout)?;
        }

        if let Some(negotiation) = self.version_negotiation.as_ref() {
            negotiation.set_opt(easy)?;
        }

        #[allow(unsafe_code)]
        {
            if let Some(enable) = self.automatic_decompression {
                if enable {
                    // Enable automatic decompression, and also populate the
                    // Accept-Encoding header with all supported encodings if not
                    // explicitly set.
                    easy.accept_encoding("")?;
                } else {
                    // Use raw FFI because safe wrapper doesn't let us set to null.
                    unsafe {
                        match curl_sys::curl_easy_setopt(
                            easy.raw(),
                            curl_sys::CURLOPT_ACCEPT_ENCODING,
                            0,
                        ) {
                            curl_sys::CURLE_OK => {}
                            code => return Err(curl::Error::new(code)),
                        }
                    }
                }
            }
        }

        if let Some(auth) = self.authentication.as_ref() {
            auth.set_opt(easy)?;
        }

        if let Some(credentials) = self.credentials.as_ref() {
            credentials.set_opt(easy)?;
        }

        if let Some(interval) = self.tcp_keepalive {
            easy.tcp_keepalive(true)?;
            easy.tcp_keepintvl(interval)?;
        }

        if let Some(enable) = self.tcp_nodelay {
            easy.tcp_nodelay(enable)?;
        }

        if let Some(interface) = self.interface.as_ref() {
            interface.set_opt(easy)?;
        }

        if let Some(version) = self.ip_version.as_ref() {
            version.set_opt(easy)?;
        }

        if let Some(dialer) = self.dial.as_ref() {
            dialer.set_opt(easy)?;
        }

        if let Some(proxy) = self.proxy.as_ref() {
            match proxy {
                Some(uri) => easy.proxy(&format!("{}", uri))?,
                None => easy.proxy("")?,
            }
        }

        if let Some(blacklist) = self.proxy_blacklist.as_ref() {
            blacklist.set_opt(easy)?;
        }

        if let Some(auth) = self.proxy_authentication.as_ref() {
            auth.set_opt(easy)?;
        }

        if let Some(credentials) = self.proxy_credentials.as_ref() {
            credentials.set_opt(easy)?;
        }

        if let Some(max) = self.max_upload_speed {
            easy.max_send_speed(max)?;
        }

        if let Some(max) = self.max_download_speed {
            easy.max_recv_speed(max)?;
        }

        if let Some(cert) = self.ssl_client_certificate.as_ref() {
            cert.set_opt(easy)?;
        }

        if let Some(cert) = self.ssl_ca_certificate.as_ref() {
            cert.set_opt(easy)?;
        }

        if let Some(ciphers) = self.ssl_ciphers.as_ref() {
            ciphers.set_opt(easy)?;
        }

        if let Some(options) = self.ssl_options.as_ref() {
            options.set_opt(easy)?;
        }

        if let Some(enable) = self.enable_metrics {
            easy.progress(enable)?;
        }

        Ok(())
    }
}
