//! Circular ring buffer with monotonic offsets and bounded UTF-8 boundary preservation.

/// Default ring buffer capacity (4 MiB). Storage grows on demand, so idle sessions cost nothing.
pub const DEFAULT_RING_BUFFER_CAPACITY: usize = 4 * 1024 * 1024;

/// Result of querying a slice from the ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceResult {
    /// Byte contents of the queried slice.
    pub data: Vec<u8>,
    /// Effective starting offset of the returned data.
    pub start_offset: u64,
    /// Ending offset (equal to current head offset).
    pub end_offset: u64,
    /// True if the client requested an offset older than the oldest retained byte.
    pub underrun: bool,
}

/// A fixed-capacity ring buffer tracking monotonic 64-bit offsets.
///
/// Ensures code point continuity on wrap-around by skipping at most 3 leading
/// continuation bytes when evicting stale data.
pub struct Utf8RingBuffer {
    storage: Vec<u8>,
    capacity: usize,
    head_offset: u64,
    tail_offset: u64,
}

impl Utf8RingBuffer {
    /// Create a new `Utf8RingBuffer` with the specified byte capacity.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be positive");
        Self {
            storage: Vec::new(),
            capacity,
            head_offset: 0,
            tail_offset: 0,
        }
    }

    /// Appends incoming byte slice into the circular buffer.
    ///
    /// Updates `head_offset`, advances `tail_offset` when capacity is exceeded,
    /// and adjusts `tail_offset` forward by at most 3 bytes to avoid starting
    /// on a mid-sequence UTF-8 continuation byte (`0x80..=0xBF`).
    pub fn write(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let cap = self.capacity;
        let new_head = self.head_offset + data.len() as u64;
        // Growth phase: nothing has wrapped yet, so head_offset == storage.len().
        if self.storage.len() < cap {
            if new_head <= cap as u64 {
                self.storage.extend_from_slice(data);
                self.head_offset = new_head;
                return data.len();
            }
            self.storage.resize(cap, 0);
        }
        // Only the newest `cap` bytes of `data` can survive.
        let skip = data.len().saturating_sub(cap);
        let mut offset = self.head_offset + skip as u64;
        let mut rest = &data[skip..];
        while !rest.is_empty() {
            let idx = (offset % cap as u64) as usize;
            let n = rest.len().min(cap - idx);
            self.storage[idx..idx + n].copy_from_slice(&rest[..n]);
            rest = &rest[n..];
            offset += n as u64;
        }
        self.head_offset = new_head;
        // Keep the existing tail adjustment:
        if self.head_offset.saturating_sub(self.tail_offset) > cap as u64 {
            let mut new_tail = self.head_offset - cap as u64;
            let max_skip = (3u64).min(cap.saturating_sub(1) as u64);
            let limit = new_tail.saturating_add(max_skip).min(self.head_offset);
            while new_tail < limit {
                let b = self.storage[(new_tail % cap as u64) as usize];
                if (b & 0b1100_0000) != 0b1000_0000 {
                    break;
                }
                new_tail += 1;
            }
            self.tail_offset = new_tail;
        }
        data.len()
    }

    /// Read data from `from_offset` up to `head_offset`.
    ///
    /// If `from_offset < tail_offset`, sets `underrun = true` and returns all
    /// currently available data from `tail_offset`.
    pub fn read_slice(&self, from_offset: u64) -> SliceResult {
        if self.head_offset == 0 || from_offset >= self.head_offset {
            return SliceResult {
                data: Vec::new(),
                start_offset: self.head_offset,
                end_offset: self.head_offset,
                underrun: false,
            };
        }

        let (effective_start, underrun) = if from_offset < self.tail_offset {
            (self.tail_offset, true)
        } else {
            (from_offset, false)
        };
        if self.storage.len() < self.capacity {
            let start = effective_start as usize;
            let end = self.head_offset as usize;
            return SliceResult {
                data: self.storage[start..end].to_vec(),
                start_offset: effective_start,
                end_offset: self.head_offset,
                underrun,
            };
        }

        let len = (self.head_offset - effective_start) as usize;
        let cap = self.capacity as u64;
        let start = (effective_start % cap) as usize;
        let first = len.min(self.capacity - start);
        let mut data = Vec::with_capacity(len);
        data.extend_from_slice(&self.storage[start..start + first]);
        data.extend_from_slice(&self.storage[..len - first]);
        SliceResult {
            data,
            start_offset: effective_start,
            end_offset: self.head_offset,
            underrun,
        }
    }

    /// Monotonic head offset (total bytes written since creation).
    #[inline]
    pub fn head_offset(&self) -> u64 {
        self.head_offset
    }

    /// Monotonic tail offset (oldest byte offset currently retained).
    #[inline]
    pub fn tail_offset(&self) -> u64 {
        self.tail_offset
    }

    /// Check if the buffer contains 0 readable bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head_offset == self.tail_offset
    }

    /// Number of bytes currently readable in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        (self.head_offset - self.tail_offset) as usize
    }

    /// Configured capacity in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
