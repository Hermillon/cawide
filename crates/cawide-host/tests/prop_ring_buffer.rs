//! Property tests for Utf8RingBuffer (crates/cawide-host/src/pty/ring_buffer.rs).

use cawide_host::pty::Utf8RingBuffer;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_utf8_ring_buffer_invariants(
        cap in 4usize..=64usize,
        chunks in prop::collection::vec(any::<String>(), 1..=16)
    ) {
        let mut buf = Utf8RingBuffer::new(cap);
        let max_total_bytes = 4 * cap;
        let mut recorded_heads = Vec::new();
        let mut total_written = 0;

        for chunk in chunks {
            if total_written >= max_total_bytes {
                break;
            }
            let bytes = chunk.as_bytes();
            let remaining = max_total_bytes - total_written;
            let take_len = bytes.len().min(remaining);
            if take_len == 0 {
                continue;
            }
            let mut sub_slice = "";
            for (idx, ch) in chunk.char_indices() {
                let end = idx + ch.len_utf8();
                if end <= take_len {
                    sub_slice = &chunk[..end];
                } else {
                    break;
                }
            }

            if sub_slice.is_empty() {
                continue;
            }

            buf.write(sub_slice.as_bytes());
            total_written += sub_slice.len();
            recorded_heads.push(buf.head_offset());
        }

        let head = buf.head_offset();
        let tail = buf.tail_offset();

        // Invariant: head - tail <= cap
        prop_assert!(head.saturating_sub(tail) <= cap as u64);

        // read_slice(tail) decodes as valid UTF-8
        let tail_slice = buf.read_slice(tail);
        prop_assert!(
            std::str::from_utf8(&tail_slice.data).is_ok(),
            "read_slice(tail) was not valid UTF-8"
        );

        // read_slice(boundary) decodes as valid UTF-8 for each write boundary >= tail
        for &boundary in &recorded_heads {
            if boundary >= tail && boundary <= head {
                let slice = buf.read_slice(boundary);
                prop_assert!(
                    std::str::from_utf8(&slice.data).is_ok(),
                    "read_slice({boundary}) was not valid UTF-8"
                );
            }
        }

        // For every from in [0, head]:
        // start_offset == max(from, tail), end_offset == head, underrun == (from < tail)
        for from in 0..=head {
            let slice = buf.read_slice(from);
            let expected_start = from.max(tail);
            prop_assert_eq!(slice.start_offset, expected_start);
            prop_assert_eq!(slice.end_offset, head);
            prop_assert_eq!(slice.underrun, from < tail);
        }
    }
}
