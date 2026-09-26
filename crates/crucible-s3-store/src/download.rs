//! Bounded download bridge between the SDK runtime and synchronous CAS reads.
//!
//! The SDK producer remains asynchronous even when a caller parks inside a
//! Tokio runtime. The reader uses a standard channel because Tokio's
//! `blocking_recv` panics on that caller thread.

use std::io::{self, Cursor, Read};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::Duration;

pub(super) enum DownloadChunk {
    Bytes(Vec<u8>),
    Error(io::Error),
    Eof,
}

pub(super) struct ChannelReader {
    chunks: Receiver<DownloadChunk>,
    current: Cursor<Vec<u8>>,
    finished: bool,
}

impl ChannelReader {
    pub(super) fn new(chunks: Receiver<DownloadChunk>) -> Self {
        Self {
            chunks,
            current: Cursor::new(Vec::new()),
            finished: false,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }

        loop {
            let read = self.current.read(output)?;
            if read != 0 {
                return Ok(read);
            }

            match self.chunks.recv() {
                Ok(DownloadChunk::Bytes(bytes)) => self.current = Cursor::new(bytes),
                Ok(DownloadChunk::Error(error)) => return Err(error),
                Ok(DownloadChunk::Eof) => {
                    self.finished = true;
                    return Ok(0);
                }
                Err(_) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            }
        }
    }
}

pub(super) async fn send_download_chunk(
    chunks: &SyncSender<DownloadChunk>,
    mut chunk: DownloadChunk,
) -> bool {
    loop {
        match chunks.try_send(chunk) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(unsent)) => chunk = unsent,
        }

        // Yield to other SDK requests while the bounded reader queue is full.
        // The enclosing command deadline can cancel this wait at any point.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronous_reader_is_safe_inside_tokio_runtime() {
        let caller_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("caller runtime");
        let sdk_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("separate SDK runtime");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let producer = sdk_runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(send_download_chunk(&sender, DownloadChunk::Bytes(vec![1, 2, 3])).await);
            assert!(send_download_chunk(&sender, DownloadChunk::Eof).await);
        });

        caller_runtime.block_on(async {
            let mut reader = ChannelReader::new(receiver);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).expect("wait inside runtime");
            assert_eq!(bytes, vec![1, 2, 3]);
        });
        sdk_runtime.block_on(producer).expect("SDK producer");
    }

    #[test]
    fn full_download_queue_yields_and_is_cancelable() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        assert!(sender.send(DownloadChunk::Bytes(vec![1])).is_ok());

        runtime.block_on(async move {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), async move {
                    send_download_chunk(&sender, DownloadChunk::Bytes(vec![2])).await
                },)
                .await
                .is_err(),
                "a full download queue must not block the SDK runtime"
            );
        });

        let mut reader = ChannelReader::new(receiver);
        let mut bytes = Vec::new();
        assert!(reader.read_to_end(&mut bytes).is_err());
        assert_eq!(bytes, vec![1]);
    }
}
