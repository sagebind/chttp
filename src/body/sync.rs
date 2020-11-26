use super::AsyncBody;
use futures_lite::{future::yield_now, io::AsyncWriteExt};
use sluice::pipe::{pipe, PipeWriter};
use std::{
    borrow::Cow,
    fmt,
    fs::File,
    io::{Cursor, ErrorKind, Read, Result},
};

/// Contains the body of a synchronous HTTP request or response.
///
/// This type is used to encapsulate the underlying stream or region of memory
/// where the contents of the body are stored. A [`Body`] can be created from
/// many types of sources using the [`Into`](std::convert::Into) trait or one of
/// its constructor functions. It can also be created from anything that
/// implements [`Read`], which [`Body`] itself also implements.
///
/// For asynchronous requests, use [`AsyncBody`] instead.
pub struct Body(Inner);

enum Inner {
    Buffer(Cursor<Cow<'static, [u8]>>),
    Reader(Box<dyn Read + Send + Sync>, Option<u64>),
}

impl Body {
    pub fn from_reader<R>(reader: R) -> Self
    where
        R: Read + Send + Sync + 'static,
    {
        Self(Inner::Reader(Box::new(reader), None))
    }

    pub fn from_reader_sized<R>(reader: R, length: u64) -> Self
    where
        R: Read + Send + Sync + 'static,
    {
        Self(Inner::Reader(Box::new(reader), Some(length)))
    }

    #[inline]
    pub fn from_bytes_static<B>(bytes: B) -> Self
    where
        B: AsRef<[u8]> + 'static
    {
        match_type! {
            <bytes as Cursor<Cow<'static, [u8]>>> => Self(Inner::Buffer(bytes)),
            <bytes as Vec<u8>> => Self::from(bytes),
            <bytes as String> => Self::from(bytes.into_bytes()),
            bytes => Self::from(bytes.as_ref().to_vec()),
        }
    }

    pub fn len(&self) -> Option<u64> {
        match &self.0 {
            Inner::Buffer(bytes) => Some(bytes.get_ref().len() as u64),
            Inner::Reader(_, len) => *len,
        }
    }

    pub fn reset(&mut self) -> bool {
        match &mut self.0 {
            Inner::Buffer(cursor) => {
                cursor.set_position(0);
                true
            }
            _ => false,
        }
    }

    /// Convert this body into an asynchronous one.
    ///
    /// Turning a synchronous operation into an asynchronous one can be quite
    /// the challenge, so this method is used internally only for limited
    /// scenarios in which this can work. If this body is an in-memory buffer,
    /// then the translation is trivial.
    ///
    /// If this body was created from an underlying synchronous reader, then we
    /// create a temporary asynchronous pipe and return a [`Writer`] which will
    /// copy the bytes from the reader to the writing half of the pipe in a
    /// blocking fashion.
    pub(crate) fn into_async(self) -> (AsyncBody, Option<Writer>) {
        match self.0 {
            Inner::Buffer(cursor) => (AsyncBody::from_bytes_static(cursor.into_inner()), None),
            Inner::Reader(reader, len) => {
                let (pipe_reader, writer) = pipe();

                (
                    if let Some(len) = len {
                        AsyncBody::from_reader_sized(pipe_reader, len)
                    } else {
                        AsyncBody::from_reader(pipe_reader)
                    },
                    Some(Writer { reader, writer }),
                )
            }
        }
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &mut self.0 {
            Inner::Buffer(cursor) => cursor.read(buf),
            Inner::Reader(reader, _) => reader.read(buf),
        }
    }
}

impl From<()> for Body {
    fn from(_: ()) -> Self {
        Self::from("")
    }
}

impl From<Vec<u8>> for Body {
    fn from(body: Vec<u8>) -> Self {
        Self(Inner::Buffer(Cursor::new(Cow::Owned(body))))
    }
}

impl From<&'_ [u8]> for Body {
    fn from(body: &[u8]) -> Self {
        body.to_vec().into()
    }
}

impl From<String> for Body {
    fn from(body: String) -> Self {
        body.into_bytes().into()
    }
}

impl From<&'_ str> for Body {
    fn from(body: &str) -> Self {
        body.as_bytes().into()
    }
}

impl From<File> for Body {
    fn from(file: File) -> Self {
        if let Ok(metadata) = file.metadata() {
            Self::from_reader_sized(file, metadata.len())
        } else {
            Self::from_reader(file)
        }
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.len() {
            Some(len) => write!(f, "Body({})", len),
            None => write!(f, "Body(?)"),
        }
    }
}

/// Helper struct for writing a synchronous reader into an asynchronous pipe.
pub(crate) struct Writer {
    reader: Box<dyn Read + Send + Sync>,
    writer: PipeWriter,
}

impl Writer {
    /// The size of the temporary buffer to use for writing. Larger buffers can
    /// improve performance, but at the cost of more memory.
    ///
    /// Curl's internal buffer size just happens to default to 16 KiB as well,
    /// so this is a natural choice.
    const BUF_SIZE: usize = 16384;

    /// Write the response body from the synchronous reader.
    ///
    /// While this function is async, it isn't a well-behaved one as it blocks
    /// frequently while reading from the request body reader. As long as this
    /// method is invoked in a controlled environment within a thread dedicated
    /// to blocking operations, this is OK.
    pub(crate) async fn write(&mut self) -> Result<()> {
        let mut buf = [0; Self::BUF_SIZE];

        loop {
            let len = match self.reader.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(len) => len,
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    yield_now().await;
                    continue;
                }
                Err(e) => return Err(e),
            };

            self.writer.write_all(&buf[..len]).await?;
        }
    }
}
