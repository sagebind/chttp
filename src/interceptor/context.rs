use crate::{Body, Error};
use super::{Interceptor, InterceptorFuture, InterceptorObj};
use http::{Request, Response};
use std::{
    fmt,
    sync::Arc,
};

/// Execution context for an interceptor.
pub struct Context<'a> {
    pub(crate) invoker: Arc<dyn (Fn(Request<Body>) -> InterceptorFuture<'a, Error>) + Send + Sync + 'a>,
    pub(crate) interceptors: &'a [InterceptorObj],
}

impl Context<'_> {
    /// Send a request.
    pub async fn send(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
        if let Some(interceptor) = self.interceptors.first() {
            let inner_context = Self {
                invoker: self.invoker.clone(),
                interceptors: &self.interceptors[1..],
            };

            match interceptor.intercept(request, inner_context).await {
                Ok(response) => Ok(response),

                // TODO: Introduce a new error variant for errors caused by an
                // interceptor. This is a temporary hack.
                Err(e) => Err(Error::Curl(e.to_string())),
            }
        } else {
            (self.invoker)(request).await
        }
    }
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").finish()
    }
}
