//! Server-Sent Events stream parser.
//!
//! Parses the SSE wire format and provides reconnection logic with
//! `Last-Event-ID` replay support.

use anyhow::{Context, Result};
use reqwest::Client;

/// A single Server-Sent Event parsed from an SSE stream.
#[derive(Debug)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
}

/// Action to take after processing an SSE event.
pub enum EventAction {
    /// Continue processing events.
    Continue,
    /// Stop the event loop (used for terminal events like "complete" or "error").
    Stop,
}

/// Parser and consumer for SSE event streams.
pub struct SseStream;

impl SseStream {
    /// Connect to an SSE endpoint via GET, consume the full response, and
    /// return the parsed events.
    ///
    /// If `last_event_id` is provided it is sent as the `Last-Event-ID` header
    /// so the server can replay missed events.
    pub async fn connect(
        client: &Client,
        url: &str,
        token: &str,
        last_event_id: Option<&str>,
    ) -> Result<Vec<SseEvent>> {
        let mut request = client
            .get(url)
            .bearer_auth(token)
            .header("Accept", "text/event-stream");

        if let Some(id) = last_event_id {
            request = request.header("Last-Event-ID", id);
        }

        let resp = request
            .send()
            .await
            .context("failed to connect to SSE endpoint")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("SSE connection failed (HTTP {status}): {body}");
        }

        let body = resp.text().await.context("failed to read SSE response body")?;

        Ok(Self::parse(&body))
    }

    /// Connect to an SSE endpoint via POST, consume the full response, and
    /// return the parsed events.
    pub async fn connect_post(
        client: &Client,
        url: &str,
        token: &str,
        last_event_id: Option<&str>,
        json_body: Option<&serde_json::Value>,
    ) -> Result<Vec<SseEvent>> {
        let mut request = client
            .post(url)
            .bearer_auth(token)
            .header("Accept", "text/event-stream");

        if let Some(id) = last_event_id {
            request = request.header("Last-Event-ID", id);
        }

        if let Some(body) = json_body {
            request = request.json(body);
        }

        let resp = request
            .send()
            .await
            .context("failed to connect to SSE endpoint (POST)")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("SSE connection failed (HTTP {status}): {body}");
        }

        let body = resp.text().await.context("failed to read SSE response body")?;

        Ok(Self::parse(&body))
    }

    /// Connect to an SSE endpoint via GET with automatic reconnection.
    pub async fn connect_with_reconnect(
        client: &Client,
        url: &str,
        token: &str,
        max_retries: u32,
        on_event: impl FnMut(&SseEvent) -> EventAction,
    ) -> Result<()> {
        Self::reconnect_loop(client, url, token, max_retries, None, on_event).await
    }

    /// Connect to an SSE endpoint via POST with automatic reconnection.
    pub async fn connect_post_with_reconnect(
        client: &Client,
        url: &str,
        token: &str,
        max_retries: u32,
        json_body: Option<&serde_json::Value>,
        on_event: impl FnMut(&SseEvent) -> EventAction,
    ) -> Result<()> {
        Self::reconnect_loop(client, url, token, max_retries, json_body, on_event).await
    }

    /// Internal reconnection loop shared by GET and POST variants.
    async fn reconnect_loop(
        client: &Client,
        url: &str,
        token: &str,
        max_retries: u32,
        json_body: Option<&serde_json::Value>,
        mut on_event: impl FnMut(&SseEvent) -> EventAction,
    ) -> Result<()> {
        let mut last_event_id: Option<String> = None;
        let mut retries = 0;

        loop {
            let result = if json_body.is_some() {
                Self::connect_post(
                    client,
                    url,
                    token,
                    last_event_id.as_deref(),
                    json_body,
                ).await
            } else {
                Self::connect(
                    client,
                    url,
                    token,
                    last_event_id.as_deref(),
                ).await
            };

            match result {
                Ok(events) => {
                    retries = 0;
                    for event in &events {
                        if let Some(ref id) = event.id {
                            last_event_id = Some(id.clone());
                        }
                        match on_event(event) {
                            EventAction::Continue => {}
                            EventAction::Stop => return Ok(()),
                        }
                    }
                    return Ok(());
                }
                Err(e) => {
                    retries += 1;
                    if retries > max_retries {
                        return Err(e).context("max SSE reconnection retries exceeded");
                    }
                    let delay = std::cmp::min(1000 * 2u64.pow(retries - 1), 5000);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }

    /// Parse raw SSE text into a list of events.
    ///
    /// The standard SSE wire format uses blank lines to delimit events. Each
    /// event block may contain `id:`, `event:`, and `data:` fields. Multiple
    /// `data:` lines within a single block are joined with newlines.
    pub fn parse(text: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();
        let mut id: Option<String> = None;
        let mut event: Option<String> = None;
        let mut data_lines: Vec<String> = Vec::new();

        for line in text.lines() {
            if line.is_empty() {
                if !data_lines.is_empty() || id.is_some() || event.is_some() {
                    events.push(SseEvent {
                        id: id.take(),
                        event: event.take(),
                        data: data_lines.join("\n"),
                    });
                    data_lines.clear();
                }
                continue;
            }

            // Lines starting with ':' are comments.
            if line.starts_with(':') {
                continue;
            }

            if let Some(value) = line.strip_prefix("id:") {
                id = Some(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("event:") {
                event = Some(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data_lines.push(value.trim_start().to_string());
            }
        }

        // Handle trailing event without blank line.
        if !data_lines.is_empty() || id.is_some() || event.is_some() {
            events.push(SseEvent {
                id: id.take(),
                event: event.take(),
                data: data_lines.join("\n"),
            });
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_events() {
        let text = "id: 0\nevent: status\ndata: {\"phase\":\"queued\"}\n\nid: 1\nevent: log\ndata: building foo\n\n";
        let events = SseStream::parse(text);
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].id.as_deref(), Some("0"));
        assert_eq!(events[0].event.as_deref(), Some("status"));
        assert_eq!(events[0].data, "{\"phase\":\"queued\"}");

        assert_eq!(events[1].id.as_deref(), Some("1"));
        assert_eq!(events[1].event.as_deref(), Some("log"));
        assert_eq!(events[1].data, "building foo");
    }

    #[test]
    fn parse_multiline_data() {
        let text = "data: line one\ndata: line two\n\n";
        let events = SseStream::parse(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line one\nline two");
    }

    #[test]
    fn parse_ignores_comments() {
        let text = ": this is a comment\ndata: hello\n\n";
        let events = SseStream::parse(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn parse_trailing_event_without_blank_line() {
        let text = "id: 5\nevent: complete\ndata: done";
        let events = SseStream::parse(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id.as_deref(), Some("5"));
        assert_eq!(events[0].event.as_deref(), Some("complete"));
        assert_eq!(events[0].data, "done");
    }

    #[test]
    fn parse_empty_input() {
        let events = SseStream::parse("");
        assert!(events.is_empty());
    }
}
