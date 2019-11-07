//! The practical HTTP client that is fun to use.
//!
//! Here are some of Isahc's key features:
//!
//! - Full support for HTTP/1.1 and HTTP/2.
//! - Configurable request timeouts.
//! - Fully asynchronous core, with asynchronous and incremental reading and
//!   writing of request and response bodies.
//! - Offers an ergonomic synchronous API as well as an asynchronous API with
//!   support for async/await.
//! - Optional automatic redirect following.
//! - Sessions and cookie persistence.
//!
//! # Getting started
//!
//! Sending requests is as easy as calling a single function. Let's make a
//! simple GET request to an example website:
//!
//! ```no_run
//! use isahc::prelude::*;
//!
//! let mut response = isahc::get("https://example.org")?;
//! println!("{}", response.text()?);
//! # Ok::<(), isahc::Error>(())
//! ```
//!
//! By default, sending a request will wait for the response, up until the
//! response headers are received. The returned response struct includes the
//! response body as an open stream implementing [`Read`](std::io::Read).
//!
//! Sending a POST request is also easy, and takes an additional argument for
//! the request body:
//!
//! ```no_run
//! let response = isahc::post("https://httpbin.org/post", "make me a salad")?;
//! # Ok::<(), isahc::Error>(())
//! ```
//!
//! Isahc provides several other simple functions for common HTTP request types:
//!
//! ```no_run
//! isahc::put("https://httpbin.org/put", "have a salad")?;
//! isahc::head("https://httpbin.org/get")?;
//! isahc::delete("https://httpbin.org/delete")?;
//! # Ok::<(), isahc::Error>(())
//! ```
//!
//! If you want to customize the request by adding headers, setting timeouts,
//! etc, then you can create a [`Request`][prelude::Request] using a
//! builder-style fluent interface, then finishing it off with a
//! [`send`][RequestExt::send]:
//!
//! ```no_run
//! use isahc::prelude::*;
//! use std::time::Duration;
//!
//! let response = Request::post("https://httpbin.org/post")
//!     .header("Content-Type", "application/json")
//!     .timeout(Duration::from_secs(5))
//!     .body(r#"{
//!         "speed": "fast",
//!         "cool_name": true
//!     }"#)?
//!     .send()?;
//! # Ok::<(), isahc::Error>(())
//! ```
//!
//! Check out the [examples] directory in the project sources for even more
//! examples.
//!
//! # Feature tour
//!
//! Below is a brief overview of some notable features of Isahc. Check out the
//! rest of the documentation for even more guides and examples.
//!
//! ## Easy request functions
//!
//! You can start sending requests without any configuration by using the global
//! functions in this module, including [`get`], [`post`], and [`send`]. These
//! use a shared HTTP client instance with sane defaults, so it is easy to get
//! up and running. They should work perfectly fine for many use-cases, so don't
//! about graduating to more complex APIs if you don't need them.
//!
//! ## Request and response traits
//!
//! Isahc includes a number of traits in the [`prelude`] module that extend the
//! [`Request`] and [`Response`] types with a plethora of extra methods that
//! make common tasks convenient and allow you to make more advanced
//! configuration.
//!
//! Some key traits to read about include [`RequestExt`], [`RequestBuilderExt`],
//! and [`ResponseExt`].
//!
//! ## Custom clients
//!
//! The free-standing functions for sending requests use a shared [`HttpClient`]
//! instance, but you can also create your own client instances, which allows
//! you to customize the default behavior for requests that use it.
//!
//! See the documentation for [`HttpClient`] and [`HttpClientBuilder`] for more
//! information on creating custom clients.
//!
//! ## Asynchronous requests
//!
//! Requests are always executed asynchronously under the hood. This allows a
//! single client to execute a large number of requests concurrently with
//! minimal overhead.
//!
//! If you are writing an asynchronous application, you can additionally benefit
//! from the async nature of the client by using the asynchronous methods
//! available to prevent blocking threads in your code. All request methods have
//! an asynchronous variant that ends with `_async` in the name. Here is our
//! first example rewritten to use async/await syntax (nightly Rust only):
//!
//! ```ignore
//! use isahc::prelude::*;
//!
//! let mut response = isahc::get_async("https://httpbin.org/get").await?;
//! println!("{}", response.text_async().await?);
//! ```
//!
//! # Logging
//!
//! Isahc logs quite a bit of useful information at various levels using the
//! [log] crate.
//!
//! If you set the log level to `Trace` for the `isahc::wire` target, Isahc will
//! also log all incoming and outgoing data while in flight. This may come in
//! handy if you are debugging code and need to see the exact data being sent to
//! the server and being received.
//!
//! [examples]: https://github.com/sagebind/isahc/tree/master/examples
//! [log]: https://docs.rs/log

#![deny(unsafe_code)]
#![warn(
    future_incompatible,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub,
    unused,
    clippy::all
)]

use http::{Request, Response};
use lazy_static::lazy_static;

#[cfg(feature = "cookies")]
pub mod cookies;

#[cfg(feature = "middleware-api")]
pub mod middleware;
#[cfg(not(feature = "middleware-api"))]
#[allow(unreachable_pub, unused)]
mod middleware;

mod agent;
mod body;
mod client;
pub mod config;
mod error;
mod handler;
mod io;
mod parse;
mod request;
mod response;
mod sys;
mod task;

pub use crate::{
    body::Body,
    client::{HttpClient, HttpClientBuilder, ResponseFuture},
    error::Error,
    request::{RequestBuilderExt, RequestExt},
    response::ResponseExt,
};

/// Re-export of the standard HTTP types.
pub use http;

/// A "prelude" for importing common Isahc types.
pub mod prelude {
    pub use crate::{Body, HttpClient, RequestBuilderExt, RequestExt, ResponseExt};

    pub use http::{Request, Response};
}

/// Send a GET request to the given URI.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::get`] for details.
pub fn get<U>(uri: U) -> Result<Response<Body>, Error>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().get(uri)
}

/// Send a GET request to the given URI asynchronously.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::get_async`] for details.
pub fn get_async<U>(uri: U) -> ResponseFuture<'static>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().get_async(uri)
}

/// Send a HEAD request to the given URI.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::head`] for details.
pub fn head<U>(uri: U) -> Result<Response<Body>, Error>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().head(uri)
}

/// Send a HEAD request to the given URI asynchronously.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::head_async`] for details.
pub fn head_async<U>(uri: U) -> ResponseFuture<'static>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().head_async(uri)
}

/// Send a POST request to the given URI with a given request body.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::post`] for details.
pub fn post<U>(uri: U, body: impl Into<Body>) -> Result<Response<Body>, Error>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().post(uri, body)
}

/// Send a POST request to the given URI asynchronously with a given request
/// body.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::post_async`] for details.
pub fn post_async<U>(uri: U, body: impl Into<Body>) -> ResponseFuture<'static>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().post_async(uri, body)
}

/// Send a PUT request to the given URI with a given request body.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::put`] for details.
pub fn put<U>(uri: U, body: impl Into<Body>) -> Result<Response<Body>, Error>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().put(uri, body)
}

/// Send a PUT request to the given URI asynchronously with a given request
/// body.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::put_async`] for details.
pub fn put_async<U>(uri: U, body: impl Into<Body>) -> ResponseFuture<'static>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().put_async(uri, body)
}

/// Send a DELETE request to the given URI.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::delete`] for details.
pub fn delete<U>(uri: U) -> Result<Response<Body>, Error>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().delete(uri)
}

/// Send a DELETE request to the given URI asynchronously.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::delete_async`] for details.
pub fn delete_async<U>(uri: U) -> ResponseFuture<'static>
where
    http::Uri: http::HttpTryFrom<U>,
{
    HttpClient::shared().delete_async(uri)
}

/// Send an HTTP request and return the HTTP response.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::send`] for details.
pub fn send<B: Into<Body>>(request: Request<B>) -> Result<Response<Body>, Error> {
    HttpClient::shared().send(request)
}

/// Send an HTTP request and return the HTTP response asynchronously.
///
/// The request is executed using a shared [`HttpClient`] instance. See
/// [`HttpClient::send_async`] for details.
pub fn send_async<B: Into<Body>>(request: Request<B>) -> ResponseFuture<'static> {
    HttpClient::shared().send_async(request)
}

/// Gets a human-readable string with the version number of Isahc and its
/// dependencies.
///
/// This function can be helpful when troubleshooting issues in Isahc or one of
/// its dependencies.
pub fn version() -> &'static str {
    static FEATURES_STRING: &str = include_str!(concat!(env!("OUT_DIR"), "/features.txt"));

    lazy_static! {
        static ref VERSION_STRING: String = format!(
            "isahc/{} (features:{}) {}",
            env!("CARGO_PKG_VERSION"),
            FEATURES_STRING,
            curl::Version::num(),
        );
    }

    &VERSION_STRING
}
