//! The HTTP client implementation.

use crate::{
    agent::{self, AgentBuilder},
    auth::{Authentication, Credentials},
    config::*,
    handler::{RequestHandler, ResponseBodyReader},
    middleware::Middleware,
    task::Join,
    Body, Error,
};
use futures_io::AsyncRead;
use futures_util::{
    future::BoxFuture,
    pin_mut,
};
use http::{Request, Response};
use lazy_static::lazy_static;
use std::{
    fmt,
    future::Future,
    io,
    iter::FromIterator,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

lazy_static! {
    static ref USER_AGENT: String = format!(
        "curl/{} isahc/{}",
        curl::Version::get().version(),
        env!("CARGO_PKG_VERSION")
    );
}

/// An HTTP client builder, capable of creating custom [`HttpClient`] instances
/// with customized behavior.
///
/// # Examples
///
/// ```
/// use isahc::config::RedirectPolicy;
/// use isahc::http;
/// use isahc::prelude::*;
/// use std::time::Duration;
///
/// let client = HttpClient::builder()
///     .timeout(Duration::from_secs(60))
///     .redirect_policy(RedirectPolicy::Limit(10))
///     .preferred_http_version(http::Version::HTTP_2)
///     .build()?;
/// # Ok::<(), isahc::Error>(())
/// ```
pub struct HttpClientBuilder {
    agent_builder: AgentBuilder,
    defaults: http::Extensions,
    middleware: Vec<Box<dyn Middleware>>,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClientBuilder {
    /// Create a new builder for building a custom client. All configuration
    /// will start out with the default values.
    ///
    /// This is equivalent to the [`Default`] implementation.
    pub fn new() -> Self {
        let mut defaults = http::Extensions::new();

        // Erase curl's default auth method of Basic.
        defaults.insert(Authentication::default());

        Self {
            agent_builder: AgentBuilder::default(),
            defaults,
            middleware: Vec::new(),
        }
    }

    /// Enable persistent cookie handling using a cookie jar.
    ///
    /// This method requires the `cookies` feature to be enabled.
    #[cfg(feature = "cookies")]
    pub fn cookies(self) -> Self {
        self.middleware_impl(crate::cookies::CookieJar::default())
    }

    /// Add a middleware layer to the client.
    ///
    /// This method requires the `middleware-api` feature to be enabled.
    #[cfg(feature = "middleware-api")]
    pub fn middleware(self, middleware: impl Middleware) -> Self {
        self.middleware_impl(middleware)
    }

    #[allow(unused)]
    fn middleware_impl(mut self, middleware: impl Middleware) -> Self {
        self.middleware.push(Box::new(middleware));
        self
    }

    /// Set a maximum number of simultaneous connections that this client is
    /// allowed to keep open at one time.
    ///
    /// If set to a value greater than zero, no more than `max` connections will
    /// be opened at one time. If executing a new request would require opening
    /// a new connection, then the request will stay in a "pending" state until
    /// an existing connection can be used or an active request completes and
    /// can be closed, making room for a new connection.
    ///
    /// Setting this value to `0` disables the limit entirely.
    ///
    /// This is an effective way of limiting the number of sockets or file
    /// descriptors that this client will open, though note that the client may
    /// use file descriptors for purposes other than just HTTP connections.
    ///
    /// By default this value is `0` and no limit is enforced.
    ///
    /// To apply a limit per-host, see
    /// [`HttpClientBuilder::max_connections_per_host`].
    pub fn max_connections(mut self, max: usize) -> Self {
        self.agent_builder = self.agent_builder.max_connections(max);
        self
    }

    /// Set a maximum number of simultaneous connections that this client is
    /// allowed to keep open to individual hosts at one time.
    ///
    /// If set to a value greater than zero, no more than `max` connections will
    /// be opened to a single host at one time. If executing a new request would
    /// require opening a new connection, then the request will stay in a
    /// "pending" state until an existing connection can be used or an active
    /// request completes and can be closed, making room for a new connection.
    ///
    /// Setting this value to `0` disables the limit entirely. By default this
    /// value is `0` and no limit is enforced.
    ///
    /// To set a global limit across all hosts, see
    /// [`HttpClientBuilder::max_connections`].
    pub fn max_connections_per_host(mut self, max: usize) -> Self {
        self.agent_builder = self.agent_builder.max_connections_per_host(max);
        self
    }

    /// Set the size of the connection cache.
    ///
    /// After requests are completed, if the underlying connection is reusable,
    /// it is added to the connection cache to be reused to reduce latency for
    /// future requests.
    ///
    /// Setting the size to `0` disables connection caching for all requests
    /// using this client.
    ///
    /// By default this value is unspecified. A reasonable default size will be
    /// chosen.
    pub fn connection_cache_size(mut self, size: usize) -> Self {
        self.agent_builder = self.agent_builder.connection_cache_size(size);
        self.defaults.insert(CloseConnection(size == 0));
        self
    }

    /// Set a timeout for the maximum time allowed for a request-response cycle.
    ///
    /// If not set, no timeout will be enforced.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.defaults.insert(Timeout(timeout));
        self
    }

    /// Set a timeout for the initial connection phase.
    ///
    /// If not set, a connect timeout of 300 seconds will be used.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.defaults.insert(ConnectTimeout(timeout));
        self
    }

    /// Set a policy for automatically following server redirects.
    ///
    /// The default is to not follow redirects.
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.defaults.insert(policy);
        self
    }

    /// Update the `Referer` header automatically when following redirects.
    pub fn auto_referer(mut self) -> Self {
        self.defaults.insert(AutoReferer);
        self
    }

    /// Set one or more default HTTP authentication methods to attempt to use
    /// when authenticating with the server.
    ///
    /// Depending on the authentication schemes enabled, you will also need to
    /// set credentials to use for authentication using
    /// [`HttpClientBuilder::credentials`].
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
    pub fn authentication(mut self, authentication: Authentication) -> Self {
        self.defaults.insert(authentication);
        self
    }

    /// Set the default credentials to use for HTTP authentication on all
    /// requests.
    ///
    /// This setting will do nothing unless you also set one or more
    /// authentication methods using [`HttpClientBuilder::authentication`].
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.defaults.insert(credentials);
        self
    }

    /// Set a preferred HTTP version the client should attempt to use to
    /// communicate to the server with.
    ///
    /// This is treated as a suggestion. A different version may be used if the
    /// server does not support it or negotiates a different version.
    pub fn preferred_http_version(mut self, version: http::Version) -> Self {
        self.defaults.insert(PreferredHttpVersion(version));
        self
    }

    /// Enable TCP keepalive with a given probe interval.
    pub fn tcp_keepalive(mut self, interval: Duration) -> Self {
        self.defaults.insert(TcpKeepAlive(interval));
        self
    }

    /// Enables the `TCP_NODELAY` option on connect.
    pub fn tcp_nodelay(mut self) -> Self {
        self.defaults.insert(TcpNoDelay);
        self
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
    /// By default the system proxy will be used, for example if one specified
    /// in either the `http_proxy` or `https_proxy` environment variables on
    /// *nix platforms.
    ///
    /// Setting to `None` explicitly disable the use of a proxy.
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
    pub fn proxy(mut self, proxy: impl Into<Option<http::Uri>>) -> Self {
        self.defaults.insert(Proxy(proxy.into()));
        self
    }

    /// Disable proxy usage to use for the provided list of hosts.
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
    pub fn proxy_blacklist(mut self, hosts: impl IntoIterator<Item = String>) -> Self {
        self.defaults.insert(ProxyBlacklist::from_iter(hosts));
        self
    }

    /// Set one or more default HTTP authentication methods to attempt to use
    /// when authenticating with a proxy.
    ///
    /// Depending on the authentication schemes enabled, you will also need to
    /// set credentials to use for authentication using
    /// [`HttpClientBuilder::proxy_credentials`].
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
    pub fn proxy_authentication(mut self, authentication: Authentication) -> Self {
        self.defaults.insert(Proxy(authentication));
        self
    }

    /// Set the default credentials to use for proxy authentication on all
    /// requests.
    ///
    /// This setting will do nothing unless you also set one or more
    /// proxy authentication methods using
    /// [`HttpClientBuilder::proxy_authentication`].
    pub fn proxy_credentials(mut self, credentials: Credentials) -> Self {
        self.defaults.insert(Proxy(credentials));
        self
    }

    /// Set a maximum upload speed for the request body, in bytes per second.
    ///
    /// The default is unlimited.
    pub fn max_upload_speed(mut self, max: u64) -> Self {
        self.defaults.insert(MaxUploadSpeed(max));
        self
    }

    /// Set a maximum download speed for the response body, in bytes per second.
    ///
    /// The default is unlimited.
    pub fn max_download_speed(mut self, max: u64) -> Self {
        self.defaults.insert(MaxDownloadSpeed(max));
        self
    }

    /// Configure DNS caching.
    ///
    /// By default, DNS entries are cached by the client executing the request
    /// and are used until the entry expires. Calling this method allows you to
    /// change the entry timeout duration or disable caching completely.
    ///
    /// Note that DNS entry TTLs are not respected, regardless of this setting.
    ///
    /// By default caching is enabled with a 60 second timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// # use isahc::config::*;
    /// # use isahc::prelude::*;
    /// # use std::time::Duration;
    /// #
    /// let client = HttpClient::builder()
    ///     // Cache entries for 10 seconds.
    ///     .dns_cache(Duration::from_secs(10))
    ///     // Cache entries forever.
    ///     .dns_cache(DnsCache::Forever)
    ///     // Don't cache anything.
    ///     .dns_cache(DnsCache::Disable)
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    pub fn dns_cache(mut self, cache: impl Into<DnsCache>) -> Self {
        // This option is per-request, but we only expose it on the client.
        // Since the DNS cache is shared between all requests, exposing this
        // option per-request would actually cause the timeout to alternate
        // values for every request with a different timeout, resulting in some
        // confusing (but valid) behavior.
        self.defaults.insert(cache.into());
        self
    }

    /// Set a list of specific DNS servers to be used for DNS resolution.
    ///
    /// By default this option is not set and the system's built-in DNS resolver
    /// is used. This option can only be used if libcurl is compiled with
    /// [c-ares](https://c-ares.haxx.se), otherwise this option has no effect.
    pub fn dns_servers(mut self, servers: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.defaults.insert(DnsServers::from_iter(servers));
        self
    }

    /// Set a custom SSL/TLS client certificate to use for all client
    /// connections.
    ///
    /// If a format is not supported by the underlying SSL/TLS engine, an error
    /// will be returned when attempting to send a request using the offending
    /// certificate.
    ///
    /// The default value is none.
    ///
    /// # Examples
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
    pub fn ssl_client_certificate(mut self, certificate: ClientCertificate) -> Self {
        self.defaults.insert(certificate);
        self
    }

    /// Set a custom SSL/TLS CA certificate bundle to use for all client
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
    pub fn ssl_ca_certificate(mut self, certificate: CaCertificate) -> Self {
        self.defaults.insert(certificate);
        self
    }

    /// Set a list of ciphers to use for SSL/TLS connections.
    ///
    /// The list of valid cipher names is dependent on the underlying SSL/TLS
    /// engine in use. You can find an up-to-date list of potential cipher names
    /// at <https://curl.haxx.se/docs/ssl-ciphers.html>.
    ///
    /// The default is unset and will result in the system defaults being used.
    pub fn ssl_ciphers(mut self, servers: impl IntoIterator<Item = String>) -> Self {
        self.defaults.insert(ssl::Ciphers::from_iter(servers));
        self
    }

    /// Set various options that control SSL/TLS behavior.
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
    /// let client = HttpClient::builder()
    ///     .ssl_options(SslOption::DANGER_ACCEPT_INVALID_CERTS | SslOption::DANGER_ACCEPT_REVOKED_CERTS)
    ///     .build()?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    pub fn ssl_options(mut self, options: SslOption) -> Self {
        self.defaults.insert(options);
        self
    }

    /// Enable comprehensive per-request metrics collection.
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
    pub fn metrics(mut self, enable: bool) -> Self {
        self.defaults.insert(EnableMetrics(enable));
        self
    }

    /// Build an [`HttpClient`] using the configured options.
    ///
    /// If the client fails to initialize, an error will be returned.
    pub fn build(self) -> Result<HttpClient, Error> {
        Ok(HttpClient {
            agent: Arc::new(self.agent_builder.spawn()?),
            defaults: self.defaults,
            middleware: self.middleware,
        })
    }
}

impl fmt::Debug for HttpClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClientBuilder").finish()
    }
}

/// An HTTP client for making requests.
///
/// An [`HttpClient`] instance acts as a session for executing one or more HTTP
/// requests, and also allows you to set common protocol settings that should be
/// applied to all requests made with the client.
///
/// [`HttpClient`] is entirely thread-safe, and implements both [`Send`] and
/// [`Sync`]. You are free to create clients outside the context of the "main"
/// thread, or move them between threads. You can even invoke many requests
/// simultaneously from multiple threads, since doing so doesn't need a mutable
/// reference to the client. This is fairly cheap to do as well, since
/// internally requests use lock-free message passing to get things going.
///
/// The client maintains a connection pool internally and is not cheap to
/// create, so we recommend creating a client once and re-using it throughout
/// your code. Creating a new client for every request would decrease
/// performance significantly, and might cause errors to occur under high
/// workloads, caused by creating too many system resources like sockets or
/// threads.
///
/// It is not universally true that you should use exactly one client instance
/// in an application. All HTTP requests made with the same client will share
/// any session-wide state, like cookies or persistent connections. It may be
/// the case that it is better to create separate clients for separate areas of
/// an application if they have separate concerns or are making calls to
/// different servers. If you are creating an API client library, that might be
/// a good place to maintain your own internal client.
///
/// # Examples
///
/// ```no_run
/// use isahc::prelude::*;
///
/// // Create a new client using reasonable defaults.
/// let client = HttpClient::new()?;
///
/// // Make some requests.
/// let mut response = client.get("https://example.org")?;
/// assert!(response.status().is_success());
///
/// println!("Response:\n{}", response.text()?);
/// # Ok::<(), isahc::Error>(())
/// ```
///
/// Customizing the client configuration:
///
/// ```no_run
/// use isahc::{config::RedirectPolicy, prelude::*};
/// use std::time::Duration;
///
/// let client = HttpClient::builder()
///     .preferred_http_version(http::Version::HTTP_11)
///     .redirect_policy(RedirectPolicy::Limit(10))
///     .timeout(Duration::from_secs(20))
///     // May return an error if there's something wrong with our configuration
///     // or if the client failed to start up.
///     .build()?;
///
/// let response = client.get("https://example.org")?;
/// assert!(response.status().is_success());
/// # Ok::<(), isahc::Error>(())
/// ```
///
/// See the documentation on [`HttpClientBuilder`] for a comprehensive look at
/// what can be configured.
pub struct HttpClient {
    /// This is how we talk to our background agent thread.
    agent: Arc<agent::Handle>,
    /// Map of config values that should be used to configure execution if not
    /// specified in a request.
    defaults: http::Extensions,
    /// Any middleware implementations that requests should pass through.
    middleware: Vec<Box<dyn Middleware>>,
}

impl HttpClient {
    /// Create a new HTTP client using the default configuration.
    ///
    /// If the client fails to initialize, an error will be returned.
    pub fn new() -> Result<Self, Error> {
        HttpClientBuilder::default().build()
    }

    /// Get a reference to a global client instance.
    ///
    /// TODO: Stabilize.
    pub(crate) fn shared() -> &'static Self {
        lazy_static! {
            static ref SHARED: HttpClient =
                HttpClient::new().expect("shared client failed to initialize");
        }
        &SHARED
    }

    /// Create a new [`HttpClientBuilder`] for building a custom client.
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::default()
    }

    /// Send a GET request to the given URI.
    ///
    /// To customize the request further, see [`HttpClient::send`]. To execute
    /// the request asynchronously, see [`HttpClient::get_async`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::prelude::*;
    ///
    /// # let client = HttpClient::new()?;
    /// let mut response = client.get("https://example.org")?;
    /// println!("{}", response.text()?);
    /// # Ok::<(), isahc::Error>(())
    /// ```
    #[inline]
    pub fn get<U>(&self, uri: U) -> Result<Response<Body>, Error>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.get_async(uri).join()
    }

    /// Send a GET request to the given URI asynchronously.
    ///
    /// To customize the request further, see [`HttpClient::send_async`]. To
    /// execute the request synchronously, see [`HttpClient::get`].
    pub fn get_async<U>(&self, uri: U) -> ResponseFuture<'_>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.send_builder_async(http::Request::get(uri), Body::empty())
    }

    /// Send a HEAD request to the given URI.
    ///
    /// To customize the request further, see [`HttpClient::send`]. To execute
    /// the request asynchronously, see [`HttpClient::head_async`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use isahc::prelude::*;
    /// # let client = HttpClient::new()?;
    /// let response = client.head("https://example.org")?;
    /// println!("Page size: {:?}", response.headers()["content-length"]);
    /// # Ok::<(), isahc::Error>(())
    /// ```
    #[inline]
    pub fn head<U>(&self, uri: U) -> Result<Response<Body>, Error>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.head_async(uri).join()
    }

    /// Send a HEAD request to the given URI asynchronously.
    ///
    /// To customize the request further, see [`HttpClient::send_async`]. To
    /// execute the request synchronously, see [`HttpClient::head`].
    pub fn head_async<U>(&self, uri: U) -> ResponseFuture<'_>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.send_builder_async(http::Request::head(uri), Body::empty())
    }

    /// Send a POST request to the given URI with a given request body.
    ///
    /// To customize the request further, see [`HttpClient::send`]. To execute
    /// the request asynchronously, see [`HttpClient::post_async`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::prelude::*;
    ///
    /// let client = HttpClient::new()?;
    ///
    /// let response = client.post("https://httpbin.org/post", r#"{
    ///     "speed": "fast",
    ///     "cool_name": true
    /// }"#)?;
    /// # Ok::<(), isahc::Error>(())
    #[inline]
    pub fn post<U>(&self, uri: U, body: impl Into<Body>) -> Result<Response<Body>, Error>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.post_async(uri, body).join()
    }

    /// Send a POST request to the given URI asynchronously with a given request
    /// body.
    ///
    /// To customize the request further, see [`HttpClient::send_async`]. To
    /// execute the request synchronously, see [`HttpClient::post`].
    pub fn post_async<U>(&self, uri: U, body: impl Into<Body>) -> ResponseFuture<'_>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.send_builder_async(http::Request::post(uri), body)
    }

    /// Send a PUT request to the given URI with a given request body.
    ///
    /// To customize the request further, see [`HttpClient::send`]. To execute
    /// the request asynchronously, see [`HttpClient::put_async`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::prelude::*;
    ///
    /// let client = HttpClient::new()?;
    ///
    /// let response = client.put("https://httpbin.org/put", r#"{
    ///     "speed": "fast",
    ///     "cool_name": true
    /// }"#)?;
    /// # Ok::<(), isahc::Error>(())
    /// ```
    #[inline]
    pub fn put<U>(&self, uri: U, body: impl Into<Body>) -> Result<Response<Body>, Error>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.put_async(uri, body).join()
    }

    /// Send a PUT request to the given URI asynchronously with a given request
    /// body.
    ///
    /// To customize the request further, see [`HttpClient::send_async`]. To
    /// execute the request synchronously, see [`HttpClient::put`].
    pub fn put_async<U>(&self, uri: U, body: impl Into<Body>) -> ResponseFuture<'_>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.send_builder_async(http::Request::put(uri), body)
    }

    /// Send a DELETE request to the given URI.
    ///
    /// To customize the request further, see [`HttpClient::send`]. To execute
    /// the request asynchronously, see [`HttpClient::delete_async`].
    #[inline]
    pub fn delete<U>(&self, uri: U) -> Result<Response<Body>, Error>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.delete_async(uri).join()
    }

    /// Send a DELETE request to the given URI asynchronously.
    ///
    /// To customize the request further, see [`HttpClient::send_async`]. To
    /// execute the request synchronously, see [`HttpClient::delete`].
    pub fn delete_async<U>(&self, uri: U) -> ResponseFuture<'_>
    where
        http::Uri: http::HttpTryFrom<U>,
    {
        self.send_builder_async(http::Request::delete(uri), Body::empty())
    }

    /// Send an HTTP request and return the HTTP response.
    ///
    /// The response body is provided as a stream that may only be consumed
    /// once.
    ///
    /// This client's configuration can be overridden for this request by
    /// configuring the request using methods provided by the
    /// [`RequestBuilderExt`](crate::prelude::RequestBuilderExt) trait.
    ///
    /// Upon success, will return a [`Response`] containing the status code,
    /// response headers, and response body from the server. The [`Response`] is
    /// returned as soon as the HTTP response headers are received; the
    /// connection will remain open to stream the response body in real time.
    /// Dropping the response body without fully consume it will close the
    /// connection early without downloading the rest of the response body.
    ///
    /// _Note that the actual underlying socket connection isn't necessarily
    /// closed on drop. It may remain open to be reused if pipelining is being
    /// used, the connection is configured as `keep-alive`, and so on._
    ///
    /// Since the response body is streamed from the server, it may only be
    /// consumed once. If you need to inspect the response body more than once,
    /// you will have to either read it into memory or write it to a file.
    ///
    /// The response body is not a direct stream from the server, but uses its
    /// own buffering mechanisms internally for performance. It is therefore
    /// undesirable to wrap the body in additional buffering readers.
    ///
    /// To execute the request asynchronously, see [`HttpClient::send_async`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use isahc::prelude::*;
    ///
    /// let client = HttpClient::new()?;
    ///
    /// let request = Request::post("https://httpbin.org/post")
    ///     .header("Content-Type", "application/json")
    ///     .body(r#"{
    ///         "speed": "fast",
    ///         "cool_name": true
    ///     }"#)?;
    ///
    /// let response = client.send(request)?;
    /// assert!(response.status().is_success());
    /// # Ok::<(), isahc::Error>(())
    /// ```
    #[inline]
    pub fn send<B: Into<Body>>(&self, request: Request<B>) -> Result<Response<Body>, Error> {
        self.send_async(request).join()
    }

    /// Send an HTTP request and return the HTTP response asynchronously.
    ///
    /// See [`HttpClient::send`] for further details.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), isahc::Error> {
    /// use isahc::prelude::*;
    ///
    /// let client = HttpClient::new()?;
    ///
    /// let request = Request::post("https://httpbin.org/post")
    ///     .header("Content-Type", "application/json")
    ///     .body(r#"{
    ///         "speed": "fast",
    ///         "cool_name": true
    ///     }"#)?;
    ///
    /// let response = client.send_async(request).await?;
    /// assert!(response.status().is_success());
    /// # Ok(()) }
    /// ```
    pub fn send_async<B: Into<Body>>(&self, request: Request<B>) -> ResponseFuture<'_> {
        let request = request.map(Into::into);

        ResponseFuture::new(self.send_async_inner(request))
    }

    fn send_builder_async(
        &self,
        mut builder: http::request::Builder,
        body: impl Into<Body>,
    ) -> ResponseFuture<'_> {
        let body = body.into();

        ResponseFuture::new(async move {
            self.send_async_inner(builder.body(body)?).await
        })
    }

    /// Actually send the request. All the public methods go through here.
    async fn send_async_inner(&self, mut request: Request<Body>) -> Result<Response<Body>, Error> {
        // Set default user agent if not specified.
        request
            .headers_mut()
            .entry(http::header::USER_AGENT)
            .unwrap()
            .or_insert(USER_AGENT.parse().unwrap());

        // Apply any request middleware, starting with the outermost one.
        for middleware in self.middleware.iter().rev() {
            request = middleware.filter_request(request);
        }

        // Create and configure a curl easy handle to fulfil the request.
        let (easy, future) = self.create_easy_handle(request)?;

        // Send the request to the agent to be executed.
        self.agent.submit_request(easy)?;

        // Await for the response headers.
        let response = future.await?;

        // If a Content-Length header is present, include that information in
        // the body as well.
        let content_length = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        // Convert the reader into an opaque Body.
        let mut response = response.map(|reader| {
            let body = ResponseBody {
                inner: reader,
                // Extend the lifetime of the agent by including a reference
                // to its handle in the response body.
                _agent: self.agent.clone(),
            };

            if let Some(len) = content_length {
                Body::reader_sized(body, len)
            } else {
                Body::reader(body)
            }
        });

        // Apply response middleware, starting with the innermost
        // one.
        for middleware in self.middleware.iter() {
            response = middleware.filter_response(response);
        }

        Ok(response)
    }

    #[allow(clippy::cognitive_complexity)]
    fn create_easy_handle(
        &self,
        request: Request<Body>,
    ) -> Result<(curl::easy::Easy2<RequestHandler>, impl Future<Output = Result<Response<ResponseBodyReader>, Error>>), Error> {
        // Prepare the request plumbing.
        let (mut parts, body) = request.into_parts();
        let has_body = !body.is_empty();
        let body_length = body.len();
        let (handler, future) = RequestHandler::new(body);

        let mut easy = curl::easy::Easy2::new(handler);

        easy.verbose(log::log_enabled!(log::Level::Debug))?;
        easy.signal(false)?;

        // Macro to apply all config values given in the request or in defaults.
        macro_rules! set_opts {
            ($easy:expr, $extensions:expr, $defaults:expr, [$($option:ty,)*]) => {{
                $(
                    if let Some(extension) = $extensions.get::<$option>().or_else(|| $defaults.get()) {
                        extension.set_opt($easy)?;
                    }
                )*
            }};
        }

        set_opts!(
            &mut easy,
            parts.extensions,
            self.defaults,
            [
                Timeout,
                ConnectTimeout,
                TcpKeepAlive,
                TcpNoDelay,
                RedirectPolicy,
                AutoReferer,
                Authentication,
                Credentials,
                MaxUploadSpeed,
                MaxDownloadSpeed,
                PreferredHttpVersion,
                Proxy<Option<http::Uri>>,
                ProxyBlacklist,
                Proxy<Authentication>,
                Proxy<Credentials>,
                DnsCache,
                DnsServers,
                ssl::Ciphers,
                ClientCertificate,
                CaCertificate,
                SslOption,
                CloseConnection,
                EnableMetrics,
            ]
        );

        // Enable automatic response decoding, unless overridden by the user via
        // a custom Accept-Encoding value.
        easy.accept_encoding(
            parts
                .headers
                .get("Accept-Encoding")
                .and_then(|value| value.to_str().ok())
                // Empty string tells curl to fill in all supported encodings.
                .unwrap_or(""),
        )?;

        // Set the HTTP method to use. Curl ties in behavior with the request
        // method, so we need to configure this carefully.
        #[allow(indirect_structural_match)]
        match (&parts.method, has_body) {
            // Normal GET request.
            (&http::Method::GET, false) => {
                easy.get(true)?;
            }
            // HEAD requests do not wait for a response payload.
            (&http::Method::HEAD, has_body) => {
                easy.upload(has_body)?;
                easy.nobody(true)?;
                easy.custom_request("HEAD")?;
            }
            // POST requests have special redirect behavior.
            (&http::Method::POST, _) => {
                easy.post(true)?;
            }
            // Normal PUT request.
            (&http::Method::PUT, _) => {
                easy.upload(true)?;
            }
            // Default case is to either treat request like a GET or PUT.
            (method, has_body) => {
                easy.upload(has_body)?;
                easy.custom_request(method.as_str())?;
            }
        }

        easy.url(&parts.uri.to_string())?;

        // If the request has a body, then we either need to tell curl how large
        // the body is if we know it, or tell curl to use chunked encoding. If
        // we do neither, curl will simply not send the body without warning.
        if has_body {
            // Use length given in Content-Length header, or the size defined by
            // the body itself.
            let body_length = parts
                .headers
                .get("Content-Length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .or(body_length);

            if let Some(len) = body_length {
                if parts.method == http::Method::POST {
                    easy.post_field_size(len)?;
                } else {
                    easy.in_filesize(len)?;
                }
            } else {
                // Set the Transfer-Encoding header to instruct curl to use
                // chunked encoding. Replaces any existing values that may be
                // incorrect.
                parts.headers.insert(
                    "Transfer-Encoding",
                    http::header::HeaderValue::from_static("chunked"),
                );
            }
        }

        // Set custom request headers.
        parts.headers.set_opt(&mut easy)?;

        Ok((easy, future))
    }
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient").finish()
    }
}

/// A future for a request being executed.
pub struct ResponseFuture<'c>(BoxFuture<'c, Result<Response<Body>, Error>>);

impl<'c> ResponseFuture<'c> {
    fn new(future: impl Future<Output = Result<Response<Body>, Error>> + Send + 'c) -> Self {
        ResponseFuture(Box::pin(future))
    }
}

impl Future for ResponseFuture<'_> {
    type Output = Result<Response<Body>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use futures_util::future::FutureExt;
        self.0.poll_unpin(cx)
    }
}

impl<'c> fmt::Debug for ResponseFuture<'c> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish()
    }
}

/// Response body stream. Holds a reference to the agent to ensure it is kept
/// alive until at least this transfer is complete.
struct ResponseBody {
    inner: ResponseBodyReader,
    _agent: Arc<agent::Handle>,
}

impl AsyncRead for ResponseBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let inner = &mut self.inner;
        pin_mut!(inner);
        inner.poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    #[test]
    fn traits() {
        is_send::<HttpClient>();
        is_sync::<HttpClient>();

        is_send::<HttpClientBuilder>();
    }
}
