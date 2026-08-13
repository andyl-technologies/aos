//! Testable protocol contract around the Cloudflare R2 bucket binding.
//!
//! JavaScript reflection stays in the wasm production adapter. Ordering,
//! bounds, metadata-before-body reads, resumable multipart identity, and
//! ambiguous abort handling live here so native tests can exercise them.

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;

use aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_CURSOR_BYTES;
use aos_hub_core::surface_write::{MultipartAbortOutcome, PartTag};

/// Cloudflare's maximum number of parts in one R2 multipart completion.
pub const MAX_R2_MULTIPART_PARTS: usize = 10_000;

/// One raw R2 listing response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R2ListPage {
    /// Full bucket keys.
    pub keys: Vec<String>,
    /// Opaque next cursor.
    pub cursor: Option<String>,
}

/// Narrow raw operations implemented by the real `worker::Bucket` adapter.
#[async_trait(?Send)]
pub trait R2BucketAdapter {
    /// Atomically writes one object.
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()>;
    /// Idempotently deletes one object.
    async fn delete(&self, key: &str) -> Result<()>;
    /// Lists one backend page.
    async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<R2ListPage>;
    /// Reads object size metadata.
    async fn head(&self, key: &str) -> Result<Option<u64>>;
    /// Reads a complete small object body.
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Creates an upload and returns its opaque id.
    async fn create_multipart(&self, key: &str) -> Result<String>;
    /// Uploads one part against a resumable `(key, upload_id)` identity.
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<String>;
    /// Completes a resumable upload with already sorted parts.
    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String>;
    /// Attempts to abort a resumable upload.
    async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()>;
}

/// Backend-independent enforcement around one R2 adapter.
pub struct R2Contract<A> {
    adapter: A,
}

impl<A> R2Contract<A>
where
    A: R2BucketAdapter,
{
    /// Wraps a raw R2 adapter.
    pub const fn new(adapter: A) -> Self {
        Self { adapter }
    }

    /// Atomically writes one object.
    pub async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.adapter.put(key, bytes).await
    }

    /// Idempotently deletes one object.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.adapter.delete(key).await
    }

    /// Reads object size metadata without requesting its body.
    pub async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.adapter.head(key).await
    }

    /// Lists and validates one raw R2 page.
    pub async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<R2ListPage> {
        if limit == 0
            || cursor.is_some_and(|value| value.len() > WORKER_MAX_SURFACE_LIST_CURSOR_BYTES)
        {
            bail!("invalid R2 listing request");
        }
        let page = self.adapter.list(prefix, cursor, limit).await?;
        if page.keys.len() > limit
            || page.cursor.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > WORKER_MAX_SURFACE_LIST_CURSOR_BYTES
            })
            || (page.cursor.is_some() && page.cursor.as_deref() == cursor)
        {
            bail!("invalid R2 listing response");
        }
        Ok(page)
    }

    /// Reads a small body only after its metadata passes the semantic cap.
    pub async fn read_bounded(&self, key: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        let Some(size) = self.adapter.head(key).await? else {
            return Ok(None);
        };
        let size = usize::try_from(size).context("R2 object size exceeds usize")?;
        if size > maximum {
            bail!("R2 object exceeds the semantic body cap");
        }
        let body = self
            .adapter
            .read(key)
            .await?
            .context("R2 object disappeared after HEAD")?;
        if body.len() != size || body.len() > maximum {
            bail!("R2 object changed after HEAD");
        }
        Ok(Some(body))
    }

    /// Creates one multipart upload.
    pub async fn create_multipart(&self, key: &str) -> Result<String> {
        self.adapter.create_multipart(key).await
    }

    /// Resumes an upload by exact key/id and writes one valid part.
    pub async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        if upload_id.is_empty() || part_number == 0 || bytes.is_empty() {
            bail!("invalid R2 multipart part");
        }
        let etag = self
            .adapter
            .upload_part(key, upload_id, part_number, bytes)
            .await?;
        if etag.is_empty() {
            bail!("R2 multipart part returned an empty ETag");
        }
        Ok(PartTag { part_number, etag })
    }

    /// Sorts and validates a complete part manifest before calling R2.
    pub async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        if upload_id.is_empty() || parts.is_empty() || parts.len() > MAX_R2_MULTIPART_PARTS {
            bail!("invalid R2 multipart completion");
        }
        let mut sorted = parts.to_vec();
        sorted.sort_by_key(|part| part.part_number);
        if sorted
            .iter()
            .any(|part| part.part_number == 0 || part.etag.is_empty())
            || sorted
                .windows(2)
                .any(|pair| pair[0].part_number == pair[1].part_number)
        {
            bail!("invalid R2 multipart completion manifest");
        }
        self.adapter
            .complete_multipart(key, upload_id, &sorted)
            .await
    }

    /// Maps any indistinguishable abort error to conservative ambiguity.
    pub async fn abort_multipart(
        &self,
        key: &str,
        upload_id: &str,
    ) -> Result<MultipartAbortOutcome> {
        if upload_id.is_empty() {
            bail!("invalid R2 multipart upload id");
        }
        Ok(match self.adapter.abort_multipart(key, upload_id).await {
            Ok(()) => MultipartAbortOutcome::Aborted,
            Err(_) => MultipartAbortOutcome::PossiblyCompleted,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    struct RecordingR2 {
        calls: RefCell<Vec<String>>,
        size: Option<u64>,
        body: Option<Vec<u8>>,
        abort_fails: Cell<bool>,
    }

    #[async_trait(?Send)]
    impl R2BucketAdapter for RecordingR2 {
        async fn put(&self, key: &str, _bytes: &[u8]) -> Result<()> {
            self.calls.borrow_mut().push(format!("put:{key}"));
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("delete:{key}"));
            Ok(())
        }
        async fn list(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            _limit: usize,
        ) -> Result<R2ListPage> {
            self.calls
                .borrow_mut()
                .push(format!("list:{prefix}:{cursor:?}"));
            Ok(R2ListPage {
                keys: vec![format!("{prefix}a")],
                cursor: Some("next".into()),
            })
        }
        async fn head(&self, key: &str) -> Result<Option<u64>> {
            self.calls.borrow_mut().push(format!("head:{key}"));
            Ok(self.size)
        }
        async fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.calls.borrow_mut().push(format!("read:{key}"));
            Ok(self.body.clone())
        }
        async fn create_multipart(&self, key: &str) -> Result<String> {
            self.calls.borrow_mut().push(format!("create:{key}"));
            Ok("upload-1".into())
        }
        async fn upload_part(
            &self,
            key: &str,
            upload_id: &str,
            part: u32,
            _bytes: &[u8],
        ) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(format!("part:{key}:{upload_id}:{part}"));
            Ok(format!("etag-{part}"))
        }
        async fn complete_multipart(
            &self,
            key: &str,
            upload_id: &str,
            parts: &[PartTag],
        ) -> Result<String> {
            self.calls.borrow_mut().push(format!(
                "complete:{key}:{upload_id}:{:?}",
                parts
                    .iter()
                    .map(|part| part.part_number)
                    .collect::<Vec<_>>()
            ));
            Ok("\"complete-etag\"".into())
        }
        async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("abort:{key}:{upload_id}"));
            if self.abort_fails.get() {
                bail!("ambiguous abort")
            }
            Ok(())
        }
    }

    fn fake(size: u64, body: Vec<u8>) -> R2Contract<RecordingR2> {
        R2Contract::new(RecordingR2 {
            calls: RefCell::new(Vec::new()),
            size: Some(size),
            body: Some(body),
            abort_fails: Cell::new(false),
        })
    }

    #[tokio::test]
    async fn contract_covers_listing_size_before_body_and_multipart_lifecycle() {
        let contract = fake(4, vec![1; 4]);
        assert_eq!(
            contract
                .list("p/", None, 2)
                .await
                .unwrap()
                .cursor
                .as_deref(),
            Some("next")
        );
        assert_eq!(
            contract.read_bounded("p/o", 4).await.unwrap(),
            Some(vec![1; 4])
        );
        assert_eq!(contract.create_multipart("p/o").await.unwrap(), "upload-1");
        let part = contract
            .upload_part("p/o", "upload-1", 2, b"xx")
            .await
            .unwrap();
        contract
            .complete_multipart(
                "p/o",
                "upload-1",
                &[
                    part,
                    PartTag {
                        part_number: 1,
                        etag: "etag-1".into(),
                    },
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            contract.abort_multipart("p/o", "upload-1").await.unwrap(),
            MultipartAbortOutcome::Aborted
        );
        let calls = contract.adapter.calls.borrow();
        assert!(calls
            .windows(2)
            .any(|pair| pair[0] == "head:p/o" && pair[1] == "read:p/o"));
        assert!(calls.iter().any(|call| call.ends_with(":[1, 2]")));
    }

    #[tokio::test]
    async fn contract_rejects_caps_and_preserves_abort_ambiguity() {
        let oversized = fake(5, vec![1; 5]);
        assert!(oversized.read_bounded("o", 4).await.is_err());
        assert!(!oversized
            .adapter
            .calls
            .borrow()
            .iter()
            .any(|call| call.starts_with("read:")));

        let ambiguous = fake(0, Vec::new());
        ambiguous.adapter.abort_fails.set(true);
        assert_eq!(
            ambiguous.abort_multipart("o", "u").await.unwrap(),
            MultipartAbortOutcome::PossiblyCompleted
        );
        let duplicate = vec![
            PartTag {
                part_number: 1,
                etag: "a".into(),
            },
            PartTag {
                part_number: 1,
                etag: "b".into(),
            },
        ];
        assert!(ambiguous
            .complete_multipart("o", "u", &duplicate)
            .await
            .is_err());
    }
}
