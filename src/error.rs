//! Types for error handling.

use curl;
use http;
use std::error::Error as StdError;
use std::fmt;
use std::io;


/// All possible types of errors that can be returned from cHTTP.
#[derive(Debug)]
pub enum Error {
    /// A problem occurred with the local certificate.
    BadClientCertificate(Option<String>),
    /// The server certificate could not be validated.
    BadServerCertificate(Option<String>),
    /// The request was canceled before it could be completed.
    Canceled,
    /// Failed to connect to the server.
    ConnectFailed,
    /// Couldn't resolve host name.
    CouldntResolveHost,
    /// Couldn't resolve proxy host name.
    CouldntResolveProxy,
    /// An unrecognized error thrown by curl.
    Curl(String),
    /// An internal error occurred in the client.
    Internal,
    /// Unrecognized or bad content encoding returned by the server.
    InvalidContentEncoding(Option<String>),
    /// Provided credentials were rejected by the server.
    InvalidCredentials,
    /// Validation error when constructing the request or parsing the response.
    InvalidHttpFormat(http::Error),
    /// JSON syntax error when constructing or parsing JSON values.
    InvalidJson,
    /// Invalid UTF-8 string error.
    InvalidUtf8,
    /// An unknown I/O error.
    Io(io::Error),
    /// The server did not send a response.
    NoResponse,
    /// The server does not support or accept range requests.
    RangeRequestUnsupported,
    /// An error occurred while writing the request body.
    RequestBodyError(Option<String>),
    /// An error occurred while reading the response body.
    ResponseBodyError(Option<String>),
    /// Failed to connect over a secure socket.
    SSLConnectFailed(Option<String>),
    /// An error ocurred in the secure socket engine.
    SSLEngineError(Option<String>),
    /// An ongoing request took longer than the configured timeout time.
    Timeout,
    /// Returned when making more simultaneous requests would exceed the configured TCP connection limit.
    TooManyConnections,
    /// Number of redirects hit the maximum amount.
    TooManyRedirects,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self, Error::description(self))
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match self {
            &Error::BadClientCertificate(Some(ref e)) => e,
            &Error::BadServerCertificate(Some(ref e)) => e,
            &Error::ConnectFailed => "failed to connect to the server",
            &Error::CouldntResolveHost => "couldn't resolve host name",
            &Error::CouldntResolveProxy => "couldn't resolve proxy host name",
            &Error::Curl(ref e) => e,
            &Error::Internal => "internal error",
            &Error::InvalidContentEncoding(Some(ref e)) => e,
            &Error::InvalidCredentials => "credentials were rejected by the server",
            &Error::InvalidHttpFormat(ref e) => e.description(),
            &Error::InvalidJson => "body is not valid JSON",
            &Error::InvalidUtf8 => "bytes are not valid UTF-8",
            &Error::Io(ref e) => e.description(),
            &Error::NoResponse => "server did not send a response",
            &Error::RangeRequestUnsupported => "server does not support or accept range requests",
            &Error::RequestBodyError(Some(ref e)) => e,
            &Error::ResponseBodyError(Some(ref e)) => e,
            &Error::SSLConnectFailed(Some(ref e)) => e,
            &Error::SSLEngineError(Some(ref e)) => e,
            &Error::Timeout => "request took longer than the configured timeout",
            &Error::TooManyConnections => "max connection limit exceeded",
            &Error::TooManyRedirects => "max redirect limit exceeded",
            _ => "unknown error",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match self {
            &Error::InvalidHttpFormat(ref e) => Some(e),
            &Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<curl::Error> for Error {
    fn from(error: curl::Error) -> Error {
        if error.is_ssl_certproblem() || error.is_ssl_cacert_badfile() {
            Error::BadClientCertificate(error.extra_description().map(str::to_owned))
        } else if error.is_peer_failed_verification() || error.is_ssl_cacert() {
            Error::BadServerCertificate(error.extra_description().map(str::to_owned))
        } else if error.is_couldnt_connect() {
            Error::ConnectFailed
        } else if error.is_couldnt_resolve_host() {
            Error::CouldntResolveHost
        } else if error.is_couldnt_resolve_proxy() {
            Error::CouldntResolveProxy
        } else if error.is_bad_content_encoding() || error.is_conv_failed() {
            Error::InvalidContentEncoding(error.extra_description().map(str::to_owned))
        } else if error.is_login_denied() {
            Error::InvalidCredentials
        } else if error.is_got_nothing() {
            Error::NoResponse
        } else if error.is_range_error() {
            Error::RangeRequestUnsupported
        } else if error.is_read_error() || error.is_aborted_by_callback() {
            Error::RequestBodyError(error.extra_description().map(str::to_owned))
        } else if error.is_write_error() || error.is_partial_file() {
            Error::ResponseBodyError(error.extra_description().map(str::to_owned))
        } else if error.is_ssl_connect_error() {
            Error::SSLConnectFailed(error.extra_description().map(str::to_owned))
        } else if error.is_ssl_engine_initfailed() || error.is_ssl_engine_notfound() || error.is_ssl_engine_setfailed() {
            Error::SSLEngineError(error.extra_description().map(str::to_owned))
        } else if error.is_operation_timedout() {
            Error::Timeout
        } else {
            Error::Curl(error.description().to_owned())
        }
    }
}

impl From<curl::MultiError> for Error {
    fn from(error: curl::MultiError) -> Error {
        Error::Curl(error.description().to_owned())
    }
}

impl From<http::Error> for Error {
    fn from(error: http::Error) -> Error {
        Error::InvalidHttpFormat(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Error::ConnectFailed,
            io::ErrorKind::TimedOut => Error::Timeout,
            _ => Error::Io(error),
        }
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::ConnectFailed => io::ErrorKind::ConnectionRefused.into(),
            Error::Io(e) => e,
            Error::Timeout => io::ErrorKind::TimedOut.into(),
            _ => io::ErrorKind::Other.into()
        }
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(_: ::std::string::FromUtf8Error) -> Error {
        Error::InvalidUtf8
    }
}

#[cfg(feature = "json")]
impl From<::json::Error> for Error {
    fn from(error: ::json::Error) -> Error {
        match error {
            ::json::Error::FailedUtf8Parsing => Error::InvalidUtf8,
            _ => Error::InvalidJson,
        }
    }
}
