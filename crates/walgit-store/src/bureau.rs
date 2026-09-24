//! Bureau's capability-scoped object-store adapter client.
//!
//! This backend speaks a deliberately small HTTP/1.1 protocol over one
//! configured Unix socket. The socket is the authority boundary: there is no
//! network, cloud-store, alternate-socket, or Bureau control-socket fallback.

use std::{
    convert::Infallible,
    error::Error,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST},
    request::Builder,
};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::{Frame, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;

use crate::{
    BoxStream, ByteStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode,
    PutOptions, Result, StoreError, Version, util,
};

const PROTOCOL_VERSION: &str = "1";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const FILE_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_NDJSON_RECORD_BYTES: usize = 64 * 1024;

const HEADER_PROTOCOL: &str = "x-walgit-store-protocol";
const HEADER_KEY: &str = "x-walgit-key";
const HEADER_VERSION: &str = "x-walgit-version";
const HEADER_SIZE: &str = "x-walgit-size";
const HEADER_IF_MATCH: &str = "x-walgit-if-match";
const HEADER_IF_NONE_MATCH: &str = "x-walgit-if-none-match";
const HEADER_RANGE_START: &str = "x-walgit-range-start";
const HEADER_RANGE_END: &str = "x-walgit-range-end";
const HEADER_PUT_MODE: &str = "x-walgit-put-mode";
const HEADER_IMMUTABLE: &str = "x-walgit-immutable";
const HEADER_PREFIX: &str = "x-walgit-prefix";
const HEADER_START_AFTER: &str = "x-walgit-start-after";

const PATH_HEALTH: &str = "/v1/health";
const PATH_OBJECT: &str = "/v1/object";
const PATH_OBJECTS: &str = "/v1/objects";
const PATH_PREFIXES: &str = "/v1/prefixes";

const NDJSON_CONTENT_TYPE: &str = "application/x-ndjson";

type BoxError = Box<dyn Error + Send + Sync>;
type RequestBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Clone)]
struct RequestBodyState(Arc<AtomicU8>);

impl RequestBodyState {
    const VALID: u8 = 0;
    const TRUNCATED: u8 = 1;
    const OVERLONG: u8 = 2;

    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(Self::VALID)))
    }

    fn record(&self, state: u8) {
        self.0.store(state, Ordering::Relaxed);
    }

    fn error(&self) -> Option<&'static str> {
        match self.0.load(Ordering::Relaxed) {
            Self::TRUNCATED => Some("PUT body ended before its declared length"),
            Self::OVERLONG => Some("PUT body exceeded its declared length"),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BureauStore {
    socket: Arc<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObjectMeta {
    key: String,
    size: u64,
    version: String,
}

impl BureauStore {
    /// Connect to the configured capability socket and verify the exact protocol.
    pub async fn new(cfg: &walgit_config::StoreConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            cfg.bureau.socket.is_absolute(),
            "store.bureau.socket must be an absolute path"
        );
        let store = Self {
            socket: Arc::new(cfg.bureau.socket.clone()),
        };
        let request = request_builder(Method::GET, PATH_HEALTH)
            .body(empty_body())
            .map_err(|error| anyhow!("building Bureau store health request: {error}"))?;
        let response = tokio::time::timeout(CONNECT_TIMEOUT, store.send(request))
            .await
            .map_err(|_| {
                anyhow!(
                    "Bureau object-store handshake timed out after {} seconds",
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
            .map_err(|error| anyhow!("Bureau object-store handshake failed: {error}"))?;
        anyhow::ensure!(
            response.status() == StatusCode::NO_CONTENT,
            "Bureau object-store handshake returned {}, expected 204",
            response.status()
        );
        let version = one_header(response.headers(), HEADER_PROTOCOL)
            .map_err(|error| anyhow!("Bureau object-store handshake failed: {error}"))?
            .ok_or_else(|| anyhow!("Bureau object-store handshake omitted {HEADER_PROTOCOL}"))?;
        anyhow::ensure!(
            version == PROTOCOL_VERSION,
            "Bureau object-store protocol is {version:?}, expected {PROTOCOL_VERSION:?}"
        );
        Ok(store)
    }

    async fn send(&self, request: Request<RequestBody>) -> Result<Response<Incoming>> {
        let body_state = request.extensions().get::<RequestBodyState>().cloned();
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&*self.socket))
            .await
            .map_err(|_| {
                StoreError::retryable(anyhow!(
                    "timed out connecting to Bureau object-store socket {}",
                    self.socket.display()
                ))
            })?
            .map_err(|error| {
                StoreError::retryable(anyhow!(
                    "connecting to Bureau object-store socket {}: {error}",
                    self.socket.display()
                ))
            })?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| StoreError::retryable(anyhow!("Bureau HTTP handshake: {error}")))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "Bureau object-store HTTP connection ended");
            }
        });
        match sender.send_request(request).await {
            Ok(response) => Ok(response),
            Err(_)
                if body_state
                    .as_ref()
                    .and_then(RequestBodyState::error)
                    .is_some() =>
            {
                Err(StoreError::InvalidArgument(
                    body_state
                        .and_then(|state| state.error())
                        .unwrap_or("invalid PUT body")
                        .to_owned(),
                ))
            }
            Err(error) => Err(StoreError::retryable(anyhow!(
                "Bureau object-store request: {error}"
            ))),
        }
    }

    async fn object_list_stream(
        &self,
        prefix: String,
        start_after: Option<String>,
    ) -> Result<BoxStream<'static, Result<ObjectMeta>>> {
        let mut builder = request_builder(Method::GET, PATH_OBJECTS);
        builder = encoded_header(builder, HEADER_PREFIX, &prefix)?;
        if let Some(start_after) = &start_after {
            builder = encoded_header(builder, HEADER_START_AFTER, start_after)?;
        }
        let request = build_request(builder, empty_body())?;
        let response = self.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), &prefix, response.headers()));
        }
        require_ndjson(response.headers())?;

        let mut previous: Option<String> = None;
        let requested_prefix = prefix;
        let requested_start = start_after;
        let stream = ndjson_lines(response.into_body()).map(move |line| {
            let line = line?;
            let wire: WireObjectMeta = serde_json::from_slice(&line)
                .map_err(|error| protocol_error(format!("invalid object-list record: {error}")))?;
            if wire.version.is_empty() {
                return Err(protocol_error("object-list record has an empty version"));
            }
            if !wire.key.starts_with(&requested_prefix) {
                return Err(protocol_error(format!(
                    "object-list key {:?} is outside prefix {:?}",
                    wire.key, requested_prefix
                )));
            }
            if requested_start
                .as_deref()
                .is_some_and(|start| wire.key.as_str() <= start)
            {
                return Err(protocol_error(format!(
                    "object-list key {:?} is not after {:?}",
                    wire.key, requested_start
                )));
            }
            if previous
                .as_deref()
                .is_some_and(|prior| wire.key.as_str() <= prior)
            {
                return Err(protocol_error(format!(
                    "object-list key {:?} is not strictly after {:?}",
                    wire.key, previous
                )));
            }
            previous = Some(wire.key.clone());
            Ok(ObjectMeta {
                key: wire.key,
                size: wire.size,
                version: Version::new(wire.version),
            })
        });
        Ok(Box::pin(stream))
    }
}

#[async_trait::async_trait]
impl ObjectStore for BureauStore {
    fn backend(&self) -> &'static str {
        "bureau"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult> {
        let mut builder = request_builder(Method::GET, PATH_OBJECT);
        builder = encoded_header(builder, HEADER_KEY, key)?;
        if let Some(version) = &opts.if_match {
            builder = encoded_header(builder, HEADER_IF_MATCH, version.as_str())?;
        }
        if let Some(version) = &opts.if_none_match {
            builder = encoded_header(builder, HEADER_IF_NONE_MATCH, version.as_str())?;
        }
        if let Some(range) = &opts.range {
            builder = builder
                .header(HEADER_RANGE_START, range.start.to_string())
                .header(HEADER_RANGE_END, range.end.to_string());
        }
        let request = build_request(builder, empty_body())?;
        let response = self.send(request).await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            let version = required_version(response.headers())?;
            let expected = opts.if_none_match.as_ref().ok_or_else(|| {
                protocol_error("adapter returned 304 without an if-none-match request")
            })?;
            if &version != expected {
                return Err(protocol_error(format!(
                    "adapter returned 304 for version {version}, requested {expected}"
                )));
            }
            return Ok(GetResult::NotModified { version });
        }

        let expected_status = if opts.range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };
        if response.status() != expected_status {
            return Err(status_error(response.status(), key, response.headers()));
        }
        let meta = required_meta(response.headers(), key)?;
        let content_length = required_u64_header(response.headers(), CONTENT_LENGTH.as_str())?;
        let expected_length = match &opts.range {
            Some(range) => {
                let start = range.start.min(meta.size);
                let end = range.end.min(meta.size);
                if start > end {
                    return Err(protocol_error(format!(
                        "adapter accepted invalid range {range:?} for object size {}",
                        meta.size
                    )));
                }
                end - start
            }
            None => meta.size,
        };
        if content_length != expected_length {
            return Err(protocol_error(format!(
                "GET content length {content_length} does not match expected {expected_length}"
            )));
        }
        let body = exact_response_body(response.into_body(), expected_length);
        Ok(GetResult::Object { meta, body })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let mut builder = request_builder(Method::HEAD, PATH_OBJECT);
        builder = encoded_header(builder, HEADER_KEY, key)?;
        let request = build_request(builder, empty_body())?;
        let response = self.send(request).await?;
        match response.status() {
            StatusCode::OK => Ok(Some(required_meta(response.headers(), key)?)),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(status_error(status, key, response.headers())),
        }
    }

    async fn put(&self, key: &str, body: PutBody, opts: PutOptions) -> Result<ObjectMeta> {
        let (length, body, body_state) = request_body(body).await?;
        let PutOptions {
            mode,
            content_type,
            immutable,
        } = opts;
        let mut builder = request_builder(Method::PUT, PATH_OBJECT)
            .header(CONTENT_LENGTH, length.to_string())
            .header(HEADER_IMMUTABLE, if immutable { "true" } else { "false" });
        builder = encoded_header(builder, HEADER_KEY, key)?;
        builder = match mode {
            PutMode::Overwrite => builder.header(HEADER_PUT_MODE, "overwrite"),
            PutMode::Create => builder.header(HEADER_PUT_MODE, "create"),
            PutMode::Update(version) => encoded_header(
                builder.header(HEADER_PUT_MODE, "update"),
                HEADER_IF_MATCH,
                version.as_str(),
            )?,
        };
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        let mut request = build_request(builder, body)?;
        request.extensions_mut().insert(body_state);
        let response = self.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), key, response.headers()));
        }
        let meta = required_meta(response.headers(), key)?;
        if meta.size != length {
            return Err(protocol_error(format!(
                "PUT response size {} does not match request length {length}",
                meta.size
            )));
        }
        Ok(meta)
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<()> {
        let mut builder = request_builder(Method::DELETE, PATH_OBJECT);
        builder = encoded_header(builder, HEADER_KEY, key)?;
        if let Some(version) = &if_version {
            builder = encoded_header(builder, HEADER_IF_MATCH, version.as_str())?;
        }
        let request = build_request(builder, empty_body())?;
        let response = self.send(request).await?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND if if_version.is_none() => Ok(()),
            status => Err(status_error(status, key, response.headers())),
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        let store = self.clone();
        let prefix = prefix.to_owned();
        let start_after = start_after.map(str::to_owned);
        Box::pin(
            futures::stream::once(
                async move { store.object_list_stream(prefix, start_after).await },
            )
            .try_flatten(),
        )
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>> {
        if !prefix.is_empty() && !prefix.ends_with('/') {
            return Err(StoreError::InvalidArgument(format!(
                "list_prefixes prefix must end in '/': {prefix:?}"
            )));
        }
        let mut builder = request_builder(Method::GET, PATH_PREFIXES);
        builder = encoded_header(builder, HEADER_PREFIX, prefix)?;
        let request = build_request(builder, empty_body())?;
        let response = self.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), prefix, response.headers()));
        }
        require_ndjson(response.headers())?;

        let mut lines = ndjson_lines(response.into_body());
        let mut output = Vec::new();
        let mut previous: Option<String> = None;
        while let Some(line) = lines.next().await {
            let line = line?;
            let value: String = serde_json::from_slice(&line)
                .map_err(|error| protocol_error(format!("invalid prefix-list record: {error}")))?;
            let Some(rest) = value.strip_prefix(prefix) else {
                return Err(protocol_error(format!(
                    "listed prefix {value:?} is outside {prefix:?}"
                )));
            };
            let Some(segment) = rest.strip_suffix('/') else {
                return Err(protocol_error(format!(
                    "listed prefix {value:?} does not end in '/'"
                )));
            };
            if segment.is_empty() || segment.contains('/') {
                return Err(protocol_error(format!(
                    "listed prefix {value:?} is not an immediate child of {prefix:?}"
                )));
            }
            if previous
                .as_deref()
                .is_some_and(|prior| value.as_str() <= prior)
            {
                return Err(protocol_error(format!(
                    "listed prefix {value:?} is not strictly after {previous:?}"
                )));
            }
            previous = Some(value.clone());
            output.push(value);
        }
        Ok(output)
    }
}

fn request_builder(method: Method, path: &'static str) -> Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, "walgit-bureau-store")
}

fn build_request(builder: Builder, body: RequestBody) -> Result<Request<RequestBody>> {
    builder
        .body(body)
        .map_err(|error| protocol_error(format!("building Bureau object-store request: {error}")))
}

fn empty_body() -> RequestBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| -> BoxError { match never {} })
        .boxed_unsync()
}

fn encoded_header(builder: Builder, name: &'static str, value: &str) -> Result<Builder> {
    let encoded = URL_SAFE_NO_PAD.encode(value.as_bytes());
    let value = HeaderValue::from_str(&encoded)
        .map_err(|error| protocol_error(format!("encoding {name}: {error}")))?;
    Ok(builder.header(name, value))
}

fn one_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(protocol_error(format!("duplicate {name} header")));
    }
    value
        .to_str()
        .map(Some)
        .map_err(|error| protocol_error(format!("invalid {name} header: {error}")))
}

fn decoded_header(headers: &HeaderMap, name: &'static str) -> Result<Option<String>> {
    let Some(encoded) = one_header(headers, name)? else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| protocol_error(format!("invalid base64url {name}: {error}")))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| protocol_error(format!("non-UTF-8 {name}: {error}")))
}

fn required_decoded_header(headers: &HeaderMap, name: &'static str) -> Result<String> {
    decoded_header(headers, name)?.ok_or_else(|| protocol_error(format!("response omitted {name}")))
}

fn required_version(headers: &HeaderMap) -> Result<Version> {
    let version = required_decoded_header(headers, HEADER_VERSION)?;
    if version.is_empty() {
        return Err(protocol_error("response has an empty version"));
    }
    Ok(Version::new(version))
}

fn required_u64_header(headers: &HeaderMap, name: &'static str) -> Result<u64> {
    let value = one_header(headers, name)?
        .ok_or_else(|| protocol_error(format!("response omitted {name}")))?;
    value
        .parse::<u64>()
        .map_err(|error| protocol_error(format!("invalid {name} value {value:?}: {error}")))
}

fn required_meta(headers: &HeaderMap, expected_key: &str) -> Result<ObjectMeta> {
    let key = required_decoded_header(headers, HEADER_KEY)?;
    if key != expected_key {
        return Err(protocol_error(format!(
            "response key {key:?} does not match request key {expected_key:?}"
        )));
    }
    Ok(ObjectMeta {
        key,
        size: required_u64_header(headers, HEADER_SIZE)?,
        version: required_version(headers)?,
    })
}

fn status_error(status: StatusCode, key: &str, headers: &HeaderMap) -> StoreError {
    match status {
        StatusCode::NOT_FOUND => StoreError::NotFound {
            key: key.to_owned(),
        },
        StatusCode::PRECONDITION_FAILED => match decoded_header(headers, HEADER_VERSION) {
            Ok(Some(current)) if current.is_empty() => {
                protocol_error("precondition response has an empty version")
            }
            Ok(current) => StoreError::PreconditionFailed {
                key: key.to_owned(),
                current: current.map(Version::new),
            },
            Err(error) => error,
        },
        StatusCode::BAD_REQUEST => StoreError::InvalidArgument(format!(
            "Bureau object-store adapter rejected request for {key:?}"
        )),
        StatusCode::TOO_MANY_REQUESTS => StoreError::retryable(anyhow!(
            "Bureau object-store adapter returned {status} for {key:?}"
        )),
        status if status.is_server_error() => StoreError::retryable(anyhow!(
            "Bureau object-store adapter returned {status} for {key:?}"
        )),
        _ => protocol_error(format!(
            "unexpected Bureau object-store status {status} for {key:?}"
        )),
    }
}

fn require_ndjson(headers: &HeaderMap) -> Result<()> {
    let content_type = one_header(headers, CONTENT_TYPE.as_str())?
        .ok_or_else(|| protocol_error("list response omitted content-type"))?;
    if content_type != NDJSON_CONTENT_TYPE {
        return Err(protocol_error(format!(
            "list response content-type is {content_type:?}, expected {NDJSON_CONTENT_TYPE:?}"
        )));
    }
    Ok(())
}

async fn request_body(body: PutBody) -> Result<(u64, RequestBody, RequestBodyState)> {
    let (length, stream) = match body {
        PutBody::Bytes(bytes) => (bytes.len() as u64, util::once(bytes)),
        PutBody::Stream { len, stream } => (len, stream),
        PutBody::File(path) => {
            let metadata = tokio::fs::metadata(&path)
                .await
                .map_err(StoreError::other)?;
            if !metadata.is_file() {
                return Err(StoreError::InvalidArgument(format!(
                    "PUT body is not a regular file: {}",
                    path.display()
                )));
            }
            let length = metadata.len();
            (length, util::file_stream(path, None, FILE_CHUNK_BYTES))
        }
    };
    let state = RequestBodyState::new();
    let frames = exact_request_stream(stream, length, state.clone()).map(|result| {
        result
            .map(Frame::data)
            .map_err(|error| Box::new(error) as BoxError)
    });
    Ok((length, StreamBody::new(frames).boxed_unsync(), state))
}

fn exact_request_stream(source: ByteStream, expected: u64, state: RequestBodyState) -> ByteStream {
    exact_stream(source, expected, Some(state))
}

fn exact_response_body(body: Incoming, expected: u64) -> ByteStream {
    let source = Box::pin(body.into_data_stream().map(|result| {
        result.map_err(|error| {
            StoreError::retryable(anyhow!(
                "reading Bureau object-store response body: {error}"
            ))
        })
    }));
    exact_stream(source, expected, None)
}

fn exact_stream(
    source: ByteStream,
    expected: u64,
    request_state: Option<RequestBodyState>,
) -> ByteStream {
    struct State {
        source: ByteStream,
        remaining: u64,
    }

    let state = State {
        source,
        remaining: expected,
    };
    Box::pin(futures::stream::try_unfold(state, move |mut state| {
        let request_state = request_state.clone();
        async move {
            loop {
                match state.source.next().await {
                    Some(Ok(chunk)) if chunk.is_empty() => {}
                    Some(Ok(chunk)) => {
                        let length = u64::try_from(chunk.len()).map_err(StoreError::other)?;
                        if length > state.remaining {
                            let message = format!(
                                "stream exceeded declared length {expected} by at least {} bytes",
                                length - state.remaining
                            );
                            return Err(if let Some(request_state) = &request_state {
                                request_state.record(RequestBodyState::OVERLONG);
                                StoreError::InvalidArgument(message)
                            } else {
                                protocol_error(message)
                            });
                        }
                        state.remaining -= length;
                        return Ok(Some((chunk, state)));
                    }
                    Some(Err(error)) => return Err(error),
                    None if state.remaining == 0 => return Ok(None),
                    None => {
                        let message = format!(
                            "stream ended {} bytes before declared length {expected}",
                            state.remaining
                        );
                        return Err(if let Some(request_state) = &request_state {
                            request_state.record(RequestBodyState::TRUNCATED);
                            StoreError::InvalidArgument(message)
                        } else {
                            protocol_error(message)
                        });
                    }
                }
            }
        }
    }))
}

fn ndjson_lines(body: Incoming) -> BoxStream<'static, Result<Bytes>> {
    struct State {
        source: ByteStream,
        buffer: BytesMut,
        pending: Bytes,
    }

    let source: ByteStream = Box::pin(body.into_data_stream().map(|result| {
        result.map_err(|error| {
            StoreError::retryable(anyhow!("reading Bureau object-store list body: {error}"))
        })
    }));
    let state = State {
        source,
        buffer: BytesMut::new(),
        pending: Bytes::new(),
    };
    Box::pin(futures::stream::try_unfold(state, |mut state| async move {
        loop {
            if let Some(newline) = state.pending.iter().position(|byte| *byte == b'\n') {
                if state.buffer.len().saturating_add(newline) > MAX_NDJSON_RECORD_BYTES {
                    return Err(protocol_error(format!(
                        "NDJSON record exceeds {MAX_NDJSON_RECORD_BYTES} bytes"
                    )));
                }
                let mut segment = state.pending.split_to(newline + 1);
                segment.truncate(newline);
                state.buffer.extend_from_slice(&segment);
                let mut line = state.buffer.split().freeze();
                if line.last() == Some(&b'\r') {
                    line.truncate(line.len() - 1);
                }
                return Ok(Some((line, state)));
            }
            if state.buffer.len().saturating_add(state.pending.len()) > MAX_NDJSON_RECORD_BYTES {
                return Err(protocol_error(format!(
                    "NDJSON record exceeds {MAX_NDJSON_RECORD_BYTES} bytes"
                )));
            }
            state.buffer.extend_from_slice(&state.pending);
            state.pending = Bytes::new();
            match state.source.next().await {
                Some(Ok(chunk)) => state.pending = chunk,
                Some(Err(error)) => return Err(error),
                None if state.buffer.is_empty() => return Ok(None),
                None => return Err(protocol_error("NDJSON response ended without a newline")),
            }
        }
    }))
}

fn protocol_error(message: impl Into<String>) -> StoreError {
    StoreError::other(anyhow!(message.into()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use bytes::Bytes;
    use futures::StreamExt;
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        task::JoinHandle,
    };

    use super::*;

    const HEALTH_OK: &[u8] = b"HTTP/1.1 204 No Content\r\n\
x-walgit-store-protocol: 1\r\n\
content-length: 0\r\n\
connection: close\r\n\
\r\n";

    struct ScriptedAdapter {
        _directory: TempDir,
        socket: PathBuf,
        task: JoinHandle<()>,
    }

    impl ScriptedAdapter {
        fn start(responses: Vec<Option<Vec<u8>>>) -> Self {
            let directory = tempfile::tempdir().expect("scripted adapter tempdir");
            let socket = directory.path().join("object-store.sock");
            let listener = UnixListener::bind(&socket).expect("bind scripted adapter");
            let task = tokio::spawn(async move {
                for response in responses {
                    let (mut stream, _) = listener.accept().await.expect("accept request");
                    read_request(&mut stream).await;
                    if let Some(response) = response {
                        stream.write_all(&response).await.expect("write response");
                        stream.shutdown().await.expect("close response");
                    }
                }
            });
            Self {
                _directory: directory,
                socket,
                task,
            }
        }

        fn config(&self) -> walgit_config::StoreConfig {
            walgit_config::StoreConfig {
                backend: walgit_config::StoreBackend::Bureau,
                bucket: String::new(),
                bureau: walgit_config::BureauConfig {
                    socket: self.socket.clone(),
                },
                ..Default::default()
            }
        }
    }

    impl Drop for ScriptedAdapter {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn read_request(stream: &mut UnixStream) {
        let mut bytes = Vec::new();
        let mut expected = None;
        loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await.expect("read request");
            if read == 0 {
                return;
            }
            bytes.extend_from_slice(&chunk[..read]);
            if expected.is_none()
                && let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let body_start = header_end + 4;
                let headers = std::str::from_utf8(&bytes[..header_end]).expect("HTTP headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                expected = Some(body_start + content_length);
            }
            if expected.is_some_and(|length| bytes.len() >= length) {
                return;
            }
        }
    }

    fn response(status: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        )
        .into_bytes();
        for (name, value) in headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(body);
        response
    }

    fn encoded(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    }

    #[tokio::test]
    async fn constructor_fails_when_socket_is_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let cfg = walgit_config::StoreConfig {
            backend: walgit_config::StoreBackend::Bureau,
            bucket: String::new(),
            bureau: walgit_config::BureauConfig {
                socket: directory.path().join("missing.sock"),
            },
            ..Default::default()
        };
        let error = BureauStore::new(&cfg).await.unwrap_err().to_string();
        assert!(error.contains("handshake failed"));
        assert!(error.contains("connecting"));
    }

    #[tokio::test]
    async fn constructor_rejects_incompatible_protocol() {
        let response = b"HTTP/1.1 204 No Content\r\n\
x-walgit-store-protocol: 2\r\n\
content-length: 0\r\n\
connection: close\r\n\
\r\n"
            .to_vec();
        let adapter = ScriptedAdapter::start(vec![Some(response)]);
        let error = BureauStore::new(&adapter.config())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("protocol is \"2\", expected \"1\""));
    }

    #[tokio::test]
    async fn opaque_version_and_response_body_are_preserved() {
        let version = "opaque/Δ token";
        let object = response(
            "200 OK",
            &[
                (HEADER_KEY, encoded("object")),
                (HEADER_VERSION, encoded(version)),
                (HEADER_SIZE, "5".to_owned()),
            ],
            b"hello",
        );
        let adapter = ScriptedAdapter::start(vec![Some(HEALTH_OK.to_vec()), Some(object)]);
        let store = BureauStore::new(&adapter.config()).await.unwrap();
        let result = store.get("object", GetOptions::default()).await.unwrap();
        let GetResult::Object { meta, body } = result else {
            panic!("expected object");
        };
        assert_eq!(meta.version.as_str(), version);
        assert_eq!(util::collect(body, 5).await.unwrap(), b"hello".as_slice());
    }

    #[tokio::test]
    async fn truncated_response_body_fails_closed() {
        let object = response(
            "200 OK",
            &[
                (HEADER_KEY, encoded("object")),
                (HEADER_VERSION, encoded("v1")),
                (HEADER_SIZE, "5".to_owned()),
            ],
            b"abc",
        );
        let mut object = object;
        let marker = b"content-length: 3";
        let offset = object
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("content-length marker");
        object.splice(
            offset..offset + marker.len(),
            b"content-length: 5".iter().copied(),
        );
        let adapter = ScriptedAdapter::start(vec![Some(HEALTH_OK.to_vec()), Some(object)]);
        let store = BureauStore::new(&adapter.config()).await.unwrap();
        let result = store.get("object", GetOptions::default()).await.unwrap();
        let GetResult::Object { body, .. } = result else {
            panic!("expected object");
        };
        assert!(util::collect(body, 5).await.is_err());
    }

    #[tokio::test]
    async fn oversized_ndjson_record_is_rejected_before_buffering_it() {
        let mut body = vec![b'x'; MAX_NDJSON_RECORD_BYTES + 1];
        body.push(b'\n');
        let listing = response(
            "200 OK",
            &[(CONTENT_TYPE.as_str(), NDJSON_CONTENT_TYPE.to_owned())],
            &body,
        );
        let adapter = ScriptedAdapter::start(vec![Some(HEALTH_OK.to_vec()), Some(listing)]);
        let store = BureauStore::new(&adapter.config()).await.unwrap();
        let error = store
            .list("", None)
            .next()
            .await
            .expect("one list result")
            .unwrap_err()
            .to_string();
        assert!(error.contains("NDJSON record exceeds"));
    }

    #[tokio::test]
    async fn truncated_put_stream_is_invalid_not_retryable() {
        let adapter = ScriptedAdapter::start(vec![Some(HEALTH_OK.to_vec()), None]);
        let store = BureauStore::new(&adapter.config()).await.unwrap();
        let error = store
            .put(
                "object",
                PutBody::Stream {
                    len: 5,
                    stream: util::once(Bytes::from_static(b"abc")),
                },
                PutOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn empty_precondition_version_is_a_protocol_error() {
        let precondition = response(
            "412 Precondition Failed",
            &[(HEADER_VERSION, String::new())],
            b"",
        );
        let adapter = ScriptedAdapter::start(vec![Some(HEALTH_OK.to_vec()), Some(precondition)]);
        let store = BureauStore::new(&adapter.config()).await.unwrap();
        let error = store
            .delete("object", Some(Version::new("expected")))
            .await
            .unwrap_err();
        assert!(!error.is_precondition_failed());
        assert!(error.to_string().contains("empty version"));
    }

    #[tokio::test]
    async fn adapter_statuses_preserve_retry_and_argument_semantics() {
        for (status, expected_retryable, expected_invalid) in [
            ("400 Bad Request", false, true),
            ("429 Too Many Requests", true, false),
            ("503 Service Unavailable", true, false),
        ] {
            let adapter = ScriptedAdapter::start(vec![
                Some(HEALTH_OK.to_vec()),
                Some(response(status, &[], b"")),
            ]);
            let store = BureauStore::new(&adapter.config()).await.unwrap();
            let error = store.head("object").await.unwrap_err();
            assert_eq!(error.is_retryable(), expected_retryable, "{status}");
            assert_eq!(
                matches!(error, StoreError::InvalidArgument(_)),
                expected_invalid,
                "{status}"
            );
        }
    }

    #[allow(dead_code)]
    fn _socket_path_is_absolute(path: &Path) {
        assert!(path.is_absolute());
    }
}
