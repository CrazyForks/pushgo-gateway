use axum::body::{Body, Bytes, to_bytes};
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, SET_COOKIE};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{Next, from_fn_with_state},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::Local;
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::{
    api::handlers::{
        channel::{
            channel_exists, channel_rename, channel_subscribe, channel_sync, channel_unsubscribe,
        },
        device::device_retire,
        push::push_to_channel,
        token::provider_token,
    },
    api::{Error, HttpResult},
    app::{AppState, AuthMode},
};

const MAX_BODY_BYTES: usize = 8 * 1024;
const MAX_LOG_BODY_BYTES: usize = 8 * 1024;

pub fn build_router(
    state: AppState,
    docs_html: &'static str,
    include_provider_token: bool,
) -> Router {
    let docs = docs_html;
    let mut router = Router::new()
        .route("/", get(move || async move { Html(docs) }))
        .route("/push", post(push_to_channel))
        .route("/channel/subscribe", post(channel_subscribe))
        .route("/channel/sync", post(channel_sync))
        .route("/channel/unsubscribe", post(channel_unsubscribe))
        .route("/channel/exists", get(channel_exists))
        .route("/channel/rename", post(channel_rename))
        .route("/device/retire", post(device_retire));

    if include_provider_token {
        router = router.route("/provider/token", get(provider_token));
    }

    router
        .layer(from_fn_with_state(state.clone(), middleware))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
        .fallback(async || (StatusCode::NOT_FOUND, "404 Not Found").into_response())
}

fn extract_bearer_token(req: &Request) -> Result<&str, Error> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Error::Unauthorized)?;

    let raw = header.to_str().map_err(|_| Error::Unauthorized)?;
    let mut it = raw.split_whitespace();

    let scheme = it.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Error::Unauthorized);
    }

    let token = it.next().ok_or(Error::Unauthorized)?;

    // Reject extra segments after the token.
    if it.next().is_some() {
        return Err(Error::Unauthorized);
    }

    // Reject empty or obviously malformed tokens.
    const MAX_TOKEN_LEN: usize = 4096;
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(Error::Unauthorized);
    }

    Ok(token)
}

async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> HttpResult {
    let start_time = Local::now();
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let version = parts.version;
    let req_headers = parts.headers.clone();

    let body_bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let resp = crate::api::err(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
            log_request(
                start_time,
                &method,
                &uri,
                version,
                &req_headers,
                None,
                Some("<unreadable body>".to_string()),
            );
            log_response(
                start_time,
                resp.status(),
                resp.headers(),
                None,
                Some("<unreadable body>".to_string()),
            );
            return Ok(resp);
        }
    };

    let request_body = format_body_for_log(&req_headers, &body_bytes);
    log_request(
        start_time,
        &method,
        &uri,
        version,
        &req_headers,
        Some(body_bytes.len()),
        request_body,
    );

    let req = Request::from_parts(parts, Body::from(body_bytes));

    if let Some(limiter) = &state.limiter
        && let Err(err) = limiter.acquire().await
    {
        let resp = err.into_response();
        log_response(start_time, resp.status(), resp.headers(), None, None);
        return Ok(resp);
    }

    fn constant_time_equals(a: &str, b: &str) -> bool {
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }
    if let AuthMode::SharedToken(token) = &state.auth {
        match extract_bearer_token(&req) {
            Ok(req_token) => {
                if !constant_time_equals(req_token, token) {
                    let resp = Error::Unauthorized.into_response();
                    log_response(start_time, resp.status(), resp.headers(), None, None);
                    return Ok(resp);
                }
            }
            Err(err) => {
                let resp = err.into_response();
                log_response(start_time, resp.status(), resp.headers(), None, None);
                return Ok(resp);
            }
        }
    }

    let resp = next.run(req).await;
    let resp_status = resp.status();
    let resp_headers = resp.headers().clone();

    let content_len = resp_headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if let Some(size) = content_len
        && size <= MAX_LOG_BODY_BYTES
    {
        let (parts, body) = resp.into_parts();
        let resp_bytes = to_bytes(body, MAX_LOG_BODY_BYTES)
            .await
            .unwrap_or_else(|_| Bytes::new());
        let response_body = format_body_for_log(&parts.headers, &resp_bytes);
        log_response(
            start_time,
            resp_status,
            &parts.headers,
            Some(resp_bytes.len()),
            response_body,
        );
        let resp = Response::from_parts(parts, Body::from(resp_bytes));
        return Ok(resp);
    }

    log_response(
        start_time,
        resp_status,
        &resp_headers,
        None,
        Some("<skipped body>".to_string()),
    );
    Ok(resp)
}

fn log_request(
    time: chrono::DateTime<chrono::Local>,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    version: axum::http::Version,
    headers: &axum::http::HeaderMap,
    body_len: Option<usize>,
    body: Option<String>,
) {
    let ts = time.format("%Y-%m-%d %H:%M:%S%.3f %:z");
    let header_text = format_headers(headers);
    println!(
        "[{ts}] REQUEST {method} {uri} {:?}\nheaders: {header_text}\nbody_len: {}\nbody: {}",
        version,
        body_len
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        body.unwrap_or_else(|| "<none>".to_string())
    );
}

fn log_response(
    start: chrono::DateTime<chrono::Local>,
    status: StatusCode,
    headers: &axum::http::HeaderMap,
    body_len: Option<usize>,
    body: Option<String>,
) {
    let end = Local::now();
    let ts = end.format("%Y-%m-%d %H:%M:%S%.3f %:z");
    let duration_ms = (end - start).num_milliseconds();
    let header_text = format_headers(headers);
    println!(
        "[{ts}] RESPONSE {status} duration_ms={duration_ms}\nheaders: {header_text}\nbody_len: {}\nbody: {}",
        body_len
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        body.unwrap_or_else(|| "<none>".to_string())
    );
}

fn format_headers(headers: &axum::http::HeaderMap) -> String {
    let mut pairs = Vec::new();
    for (name, value) in headers.iter() {
        let value = if is_sensitive_header(name) {
            "<redacted>".to_string()
        } else {
            value.to_str().unwrap_or("<binary>").to_string()
        };
        pairs.push(format!("{name}: {value}"));
    }
    pairs.join("; ")
}

fn format_body_for_log(headers: &axum::http::HeaderMap, bytes: &Bytes) -> Option<String> {
    if bytes.is_empty() {
        return Some("<empty>".to_string());
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let content_type = content_type.trim().to_ascii_lowercase();
    let is_json = content_type.contains("application/json") || content_type.contains("+json");

    if !is_textual_content_type(&content_type) {
        return Some("<binary>".to_string());
    }

    if is_json && let Ok(mut json) = serde_json::from_slice::<Value>(bytes) {
        redact_json(&mut json);
        if let Ok(rendered) = serde_json::to_string(&json) {
            return Some(rendered);
        }
    }

    Some(String::from_utf8_lossy(bytes).to_string())
}

fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *value = Value::String("<redacted>".to_string());
                } else {
                    redact_json(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        _ => {}
    }
}

fn is_textual_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || content_type.contains("application/json")
        || content_type.contains("+json")
        || content_type.contains("application/x-www-form-urlencoded")
        || content_type.contains("application/xml")
        || content_type.contains("text/xml")
}

fn is_sensitive_header(name: &axum::http::HeaderName) -> bool {
    if name == AUTHORIZATION || name == COOKIE || name == SET_COOKIE {
        return true;
    }

    matches!(
        name.as_str(),
        "proxy-authorization"
            | "x-api-key"
            | "x-api-token"
            | "x-auth-token"
            | "x-access-token"
            | "x-refresh-token"
    )
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "password"
            | "device_token"
            | "device_tokens"
            | "auth_token"
            | "token"
            | "authorization"
            | "secret"
            | "access_token"
            | "refresh_token"
            | "private_key"
            | "client_secret"
            | "api_key"
            | "key_pem"
    )
}
