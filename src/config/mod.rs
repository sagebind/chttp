//! Definition of all client and request configuration options.
//!
//! Individual options are separated out into multiple types. Each type acts
//! both as a "field name" and the value of that option.

// Options are implemented as structs of various kinds that can be "applied" to
// a curl easy handle. This helps to reduce code duplication as there are many
// supported options, and also helps avoid having a massive function that does
// all the configuring.
//
// When adding new config options, remember to add methods for setting the
// option both in HttpClientBuilder and RequestBuilderExt. In addition, be sure
// to update the client code to apply the option when configuring an easy
// handle.

use crate::auth::{Authentication, Credentials};
use curl::easy::Easy2;
use std::{
    iter::FromIterator,
    net::SocketAddr,
    time::Duration,
};

pub(crate) mod dns;
pub(crate) mod ssl;

pub use dns::DnsCache;
pub use ssl::{
    ClientCertificate,
    CaCertificate,
    PrivateKey,
    SslOption,
};

/// Provides additional methods when building a request for configuring various
/// execution-related options on how the request should be sent.
pub trait Configurable: Sized {
    /// Set a maximum amount of time that a request is allowed to take before
    /// being aborted.
    ///
    /// If not set, no timeout will be enforced.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::prelude::*;
    /// use std::time::Duration;
    ///
    /// // This page is too slow and won't respond in time.
    /// let response = Request::get("https://httpbin.org/delay/10")
    ///     .timeout(Duration::from_secs(5))
    ///     .body(())?
    ///     .send()
    ///     .expect_err("page should time out");
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn timeout(self, timeout: Duration) -> Self {
        self.configure(Timeout(timeout))
    }

    /// Set a timeout for the initial connection phase.
    ///
    /// If not set, a connect timeout of 300 seconds will be used.
    fn connect_timeout(self, timeout: Duration) -> Self {
        self.configure(ConnectTimeout(timeout))
    }

    /// Configure how the use of HTTP versions should be negotiated with the
    /// server.
    ///
    /// The default is [`HttpVersionNegotiation::latest_compatible`].
    fn version_negotiation(self, negotiation: VersionNegotiation) -> Self {
        self.configure(negotiation)
    }

    /// Set a policy for automatically following server redirects.
    ///
    /// The default is to not follow redirects.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::config::RedirectPolicy;
    /// use isahc::prelude::*;
    ///
    /// // This URL redirects us to where we want to go.
    /// let response = Request::get("https://httpbin.org/redirect/1")
    ///     .redirect_policy(RedirectPolicy::Follow)
    ///     .body(())?
    ///     .send()?;
    ///
    /// // This URL redirects too much!
    /// let error = Request::get("https://httpbin.org/redirect/10")
    ///     .redirect_policy(RedirectPolicy::Limit(5))
    ///     .body(())?
    ///     .send()
    ///     .expect_err("too many redirects");
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn redirect_policy(self, policy: RedirectPolicy) -> Self {
        self.configure(policy)
    }

    /// Update the `Referer` header automatically when following redirects.
    fn auto_referer(self) -> Self {
        self.configure(AutoReferer)
    }

    /// Set one or more default HTTP authentication methods to attempt to use
    /// when authenticating with the server.
    ///
    /// Depending on the authentication schemes enabled, you will also need to
    /// set credentials to use for authentication using
    /// [`Configurable::credentials`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::auth::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .authentication(Authentication::basic() | Authentication::digest())
    ///     .credentials(Credentials::new("clark", "qwerty"))
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn authentication(self, authentication: Authentication) -> Self {
        self.configure(authentication)
    }

    /// Set the credentials to use for HTTP authentication.
    ///
    /// This setting will do nothing unless you also set one or more
    /// authentication methods using [`Configurable::authentication`].
    fn credentials(self, credentials: Credentials) -> Self {
        self.configure(credentials)
    }

    /// Enable TCP keepalive with a given probe interval.
    fn tcp_keepalive(self, interval: Duration) -> Self {
        self.configure(TcpKeepAlive(interval))
    }

    /// Enables the `TCP_NODELAY` option on connect.
    fn tcp_nodelay(self) -> Self {
        self.configure(TcpNoDelay)
    }

    /// Set a proxy to use for requests.
    ///
    /// The proxy protocol is specified by the URI scheme.
    ///
    /// - **`http`**: Proxy. Default when no scheme is specified.
    /// - **`https`**: HTTPS Proxy. (Added in 7.52.0 for OpenSSL, GnuTLS and
    ///   NSS)
    /// - **`socks4`**: SOCKS4 Proxy.
    /// - **`socks4a`**: SOCKS4a Proxy. Proxy resolves URL hostname.
    /// - **`socks5`**: SOCKS5 Proxy.
    /// - **`socks5h`**: SOCKS5 Proxy. Proxy resolves URL hostname.
    ///
    /// By default no proxy will be used, unless one is specified in either the
    /// `http_proxy` or `https_proxy` environment variables.
    ///
    /// Setting to `None` explicitly disables the use of a proxy.
    ///
    /// # Examples
    ///
    /// Using `http://proxy:80` as a proxy:
    ///
    /// ```
    /// # use isahc::auth::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .proxy(Some("http://proxy:80".parse()?))
    ///     .build()?;
    /// # Ok::<(), Box<std::error::Error>>(())
    /// ```
    ///
    /// Explicitly disable the use of a proxy:
    ///
    /// ```
    /// # use isahc::auth::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .proxy(None)
    ///     .build()?;
    /// # Ok::<(), Box<std::error::Error>>(())
    /// ```
    fn proxy(self, proxy: impl Into<Option<http::Uri>>) -> Self {
        self.configure(Proxy(proxy.into()))
    }

    /// Disable proxy usage for the provided list of hosts.
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     // Disable proxy for specified hosts.
    ///     .proxy_blacklist(vec!["a.com".to_string(), "b.org".to_string()])
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn proxy_blacklist(self, hosts: impl IntoIterator<Item = String>) -> Self {
        self.configure(ProxyBlacklist::from_iter(hosts))
    }

    /// Set one or more HTTP authentication methods to attempt to use when
    /// authenticating with a proxy.
    ///
    /// Depending on the authentication schemes enabled, you will also need to
    /// set credentials to use for authentication using
    /// [`Configurable::proxy_credentials`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::auth::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .proxy("http://proxy:80".parse::<http::Uri>()?)
    ///     .proxy_authentication(Authentication::basic())
    ///     .proxy_credentials(Credentials::new("clark", "qwerty"))
    ///     .build()?;
    /// # Ok::<(), Box<std::error::Error>>(())
    /// ```
    fn proxy_authentication(self, authentication: Authentication) -> Self {
        self.configure(Proxy(authentication))
    }

    /// Set the credentials to use for proxy authentication.
    ///
    /// This setting will do nothing unless you also set one or more proxy
    /// authentication methods using
    /// [`Configurable::proxy_authentication`].
    fn proxy_credentials(self, credentials: Credentials) -> Self {
        self.configure(Proxy(credentials))
    }

    /// Set a maximum upload speed for the request body, in bytes per second.
    ///
    /// The default is unlimited.
    fn max_upload_speed(self, max: u64) -> Self {
        self.configure(MaxUploadSpeed(max))
    }

    /// Set a maximum download speed for the response body, in bytes per second.
    ///
    /// The default is unlimited.
    fn max_download_speed(self, max: u64) -> Self {
        self.configure(MaxDownloadSpeed(max))
    }

    /// Set a list of specific DNS servers to be used for DNS resolution.
    ///
    /// By default this option is not set and the system's built-in DNS resolver
    /// is used. This option can only be used if libcurl is compiled with
    /// [c-ares](https://c-ares.haxx.se), otherwise this option has no effect.
    fn dns_servers(self, servers: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.configure(dns::Servers::from_iter(servers))
    }

    /// Set a custom SSL/TLS client certificate to use for client connections.
    ///
    /// If a format is not supported by the underlying SSL/TLS engine, an error
    /// will be returned when attempting to send a request using the offending
    /// certificate.
    ///
    /// The default value is none.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::config::{ClientCertificate, PrivateKey};
    /// use isahc::prelude::*;
    ///
    /// let response = Request::get("localhost:3999")
    ///     .ssl_client_certificate(ClientCertificate::pem_file(
    ///         "client.pem",
    ///         PrivateKey::pem_file("key.pem", String::from("secret")),
    ///     ))
    ///     .body(())?
    ///     .send()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    ///
    /// ```
    /// # use isahc::config::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .ssl_client_certificate(ClientCertificate::pem_file(
    ///         "client.pem",
    ///         PrivateKey::pem_file("key.pem", String::from("secret")),
    ///     ))
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn ssl_client_certificate(self, certificate: ClientCertificate) -> Self {
        self.configure(certificate)
    }

    /// Set a custom SSL/TLS CA certificate bundle to use for client
    /// connections.
    ///
    /// The default value is none.
    ///
    /// # Notes
    ///
    /// On Windows it may be necessary to combine this with
    /// [`SslOption::DANGER_ACCEPT_REVOKED_CERTS`] in order to work depending on
    /// the contents of your CA bundle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::config::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .ssl_ca_certificate(CaCertificate::file("ca.pem"))
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn ssl_ca_certificate(self, certificate: CaCertificate) -> Self {
        self.configure(certificate)
    }

    /// Set a list of ciphers to use for SSL/TLS connections.
    ///
    /// The list of valid cipher names is dependent on the underlying SSL/TLS
    /// engine in use. You can find an up-to-date list of potential cipher names
    /// at <https://curl.haxx.se/docs/ssl-ciphers.html>.
    ///
    /// The default is unset and will result in the system defaults being used.
    fn ssl_ciphers(self, servers: impl IntoIterator<Item = String>) -> Self {
        self.configure(ssl::Ciphers::from_iter(servers))
    }

    /// Set various options for this request that control SSL/TLS behavior.
    ///
    /// Most options are for disabling security checks that introduce security
    /// risks, but may be required as a last resort. Note that the most secure
    /// options are already the default and do not need to be specified.
    ///
    /// The default value is [`SslOption::NONE`].
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. Using *any*
    /// options that alter how certificates are validated can introduce
    /// significant security vulnerabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::config::*;
    /// # use isahc::prelude::*;
    /// #
    /// let response = Request::get("https://badssl.com")
    ///     .ssl_options(SslOption::DANGER_ACCEPT_INVALID_CERTS | SslOption::DANGER_ACCEPT_REVOKED_CERTS)
    ///     .body(())?
    ///     .send()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    ///
    /// ```
    /// # use isahc::config::*;
    /// # use isahc::prelude::*;
    /// #
    /// let client = HttpClient::builder()
    ///     .ssl_options(SslOption::DANGER_ACCEPT_INVALID_CERTS | SslOption::DANGER_ACCEPT_REVOKED_CERTS)
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    fn ssl_options(self, options: SslOption) -> Self {
        self.configure(options)
    }

    /// Enable or disable comprehensive per-request metrics collection.
    ///
    /// When enabled, detailed timing metrics will be tracked while a request is
    /// in progress, such as bytes sent and received, estimated size, DNS lookup
    /// time, etc. For a complete list of the available metrics that can be
    /// inspected, see the [`Metrics`](crate::Metrics) documentation.
    ///
    /// When enabled, to access a view of the current metrics values you can use
    /// [`ResponseExt::metrics`](crate::ResponseExt::metrics).
    ///
    /// While effort is taken to optimize hot code in metrics collection, it is
    /// likely that enabling it will have a small effect on overall throughput.
    /// Disabling metrics may be necessary for absolute peak performance.
    ///
    /// By default metrics are disabled.
    fn metrics(self, enable: bool) -> Self {
        self.configure(EnableMetrics(enable))
    }

    #[doc(hidden)]
    fn configure<T: SetOpt>(self, option: T) -> Self;
}

impl Configurable for http::request::Builder {
    fn configure<T: SetOpt>(self, option: T) -> Self {
        self.extension(option)
    }
}

mod private {
    use curl::easy::Easy2;
    use std::any::Any;

    /// A helper trait for applying a configuration value to a given curl handle.
    pub trait SetOpt: Any + Send + Sync + 'static {
        /// Apply this configuration option to the given curl handle.
        fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error>;
    }
}

pub(crate) use private::SetOpt;

impl SetOpt for http::HeaderMap {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        let mut headers = curl::easy::List::new();

        for (name, value) in self.iter() {
            let header = format!("{}: {}", name.as_str(), value.to_str().unwrap());
            headers.append(&header)?;
        }

        easy.http_headers(headers)
    }
}

/// A strategy for selecting what HTTP versions should be used when
/// communicating with a server.
#[derive(Clone, Debug)]
pub struct VersionNegotiation {
    flag: curl::easy::HttpVersion,
    strict: bool,
}

impl Default for VersionNegotiation {
    fn default() -> Self {
        Self::latest_compatible()
    }
}

impl VersionNegotiation {
    /// Always prefer the latest supported version with a preference for old
    /// versions if necessary in order to connect. This is the default.
    ///
    /// Typically negotiation will begin with an HTTP/1.1 request, upgrading to
    /// HTTP/2 if possible, then to HTTP/3 if possible, etc.
    pub const fn latest_compatible() -> Self {
        Self {
            // In curl land, this basically the most lenient option. Alt-Svc is
            // used to upgrade to newer versions, and old versions are used if
            // the server doesn't respond to the HTTP/1.1 -> HTTP/2 upgrade.
            flag: curl::easy::HttpVersion::V2,
            strict: false,
        }
    }

    /// Connect via HTTP/1.0 and do not attempt to use a higher version.
    pub const fn http10() -> Self {
        Self {
            flag: curl::easy::HttpVersion::V10,
            strict: true,
        }
    }

    /// Connect via HTTP/1.1 and do not attempt to use a higher version.
    pub const fn http11() -> Self {
        Self {
            flag: curl::easy::HttpVersion::V11,
            strict: true,
        }
    }

    /// Connect via HTTP/2. Failure to connect will not fall back to old
    /// versions, unless HTTP/1.1 is negotiated via TLS ALPN before the session
    /// begins.
    ///
    /// If HTTP/2 support is not compiled in, then using this strategy will
    /// always result in an error.
    ///
    /// This strategy is often referred to as [HTTP/2 with Prior
    /// Knowledge](https://http2.github.io/http2-spec/#known-http).
    pub const fn http2() -> Self {
        Self {
            flag: curl::easy::HttpVersion::V2PriorKnowledge,
            strict: true,
        }
    }

    // /// Connect via HTTP/3. Failure to connect will not fall back to old
    // /// versions.
    // pub const fn http3() -> Self {
    //     Self {
    //         flag: curl::easy::HttpVersion::V3,
    //         strict: true,
    //     }
    // }
}

impl SetOpt for VersionNegotiation {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        if let Err(e) = easy.http_version(self.flag) {
            if self.strict {
                return Err(e);
            } else {
                log::debug!("failed to set HTTP version: {}", e);
            }
        }

        Ok(())
    }
}

/// Describes a policy for handling server redirects.
///
/// The default is to not follow redirects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectPolicy {
    /// Do not apply any special treatment to redirect responses. The response
    /// will be returned as-is and redirects will not be followed.
    ///
    /// This is the default policy.
    None,
    /// Follow all redirects automatically.
    Follow,
    /// Follow redirects automatically up to a maximum number of redirects.
    Limit(u32),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        RedirectPolicy::None
    }
}

impl SetOpt for RedirectPolicy {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        match self {
            RedirectPolicy::Follow => {
                easy.follow_location(true)?;
            }
            RedirectPolicy::Limit(max) => {
                easy.follow_location(true)?;
                easy.max_redirections(*max)?;
            }
            RedirectPolicy::None => {
                easy.follow_location(false)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Timeout(pub(crate) Duration);

impl SetOpt for Timeout {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.timeout(self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectTimeout(pub(crate) Duration);

impl SetOpt for ConnectTimeout {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.connect_timeout(self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TcpKeepAlive(pub(crate) Duration);

impl SetOpt for TcpKeepAlive {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.tcp_keepalive(true)?;
        easy.tcp_keepintvl(self.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpNoDelay;

impl SetOpt for TcpNoDelay {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.tcp_nodelay(true)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AutoReferer;

impl SetOpt for AutoReferer {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.autoreferer(true)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxUploadSpeed(pub(crate) u64);

impl SetOpt for MaxUploadSpeed {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.max_send_speed(self.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MaxDownloadSpeed(pub(crate) u64);

impl SetOpt for MaxDownloadSpeed {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.max_recv_speed(self.0)
    }
}

/// Decorator for marking certain configurations to apply to a proxy rather than
/// the origin itself.
#[derive(Clone, Debug)]
pub(crate) struct Proxy<T>(pub(crate) T);

/// Proxy URI specifies the type and host of a proxy to use.
impl SetOpt for Proxy<Option<http::Uri>> {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        match &self.0 {
            Some(uri) => easy.proxy(&format!("{}", uri)),
            None => easy.proxy(""),
        }
    }
}

/// A list of host names that do not require a proxy to get reached, even if one
/// is specified.
///
/// See
/// [`HttpClientBuilder::proxy_blacklist`](crate::HttpClientBuilder::proxy_blacklist)
/// for configuring a client's no proxy list.
#[derive(Clone, Debug)]
pub(crate) struct ProxyBlacklist {
    skip: String,
}

impl FromIterator<String> for ProxyBlacklist {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self {
            skip: iter.into_iter().collect::<Vec<_>>().join(","),
        }
    }
}

impl SetOpt for ProxyBlacklist {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.noproxy(&self.skip)
    }
}

/// Close the connection when the request completes instead of returning it to
/// the connection cache.
#[derive(Clone, Debug)]
pub(crate) struct CloseConnection(pub(crate) bool);

impl SetOpt for CloseConnection {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.forbid_reuse(self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnableMetrics(pub(crate) bool);

impl SetOpt for EnableMetrics {
    fn set_opt<H>(&self, easy: &mut Easy2<H>) -> Result<(), curl::Error> {
        easy.progress(self.0)
    }
}
