use cawide_host::pty::ring_buffer::{SliceResult, Utf8RingBuffer, DEFAULT_RING_BUFFER_CAPACITY};

#[test]
fn test_basic_write_and_slice() {
    let mut buf = Utf8RingBuffer::new(64);
    assert!(buf.is_empty());
    assert_eq!(buf.head_offset(), 0);
    assert_eq!(buf.tail_offset(), 0);

    let written = buf.write(b"hello world");
    assert_eq!(written, 11);
    assert!(!buf.is_empty());
    assert_eq!(buf.head_offset(), 11);
    assert_eq!(buf.tail_offset(), 0);

    let slice = buf.read_slice(0);
    assert_eq!(
        slice,
        SliceResult {
            data: b"hello world".to_vec(),
            start_offset: 0,
            end_offset: 11,
            underrun: false,
        }
    );

    // Read partial slice
    let partial = buf.read_slice(6);
    assert_eq!(
        partial,
        SliceResult {
            data: b"world".to_vec(),
            start_offset: 6,
            end_offset: 11,
            underrun: false,
        }
    );
}

#[test]
fn test_wrap_around() {
    let mut buf = Utf8RingBuffer::new(10);
    buf.write(b"0123456789abcde"); // 15 bytes into capacity 10

    assert_eq!(buf.head_offset(), 15);
    assert_eq!(buf.tail_offset(), 5);

    let slice = buf.read_slice(5);
    assert_eq!(
        slice,
        SliceResult {
            data: b"56789abcde".to_vec(),
            start_offset: 5,
            end_offset: 15,
            underrun: false,
        }
    );
}

#[test]
fn test_bounded_utf8_boundary_preservation() {
    // Capacity = 10
    let mut buf = Utf8RingBuffer::new(10);

    // Write 8 bytes: 5 ASCII + 3-byte char 'ế' (0xE1, 0xBA, 0xBF)
    // Offsets:
    // 0..5: b"hello"
    // 5: 0xE1 (lead byte)
    // 6: 0xBA (continuation byte)
    // 7: 0xBF (continuation byte)
    buf.write(b"hello\xE1\xBA\xBF");
    assert_eq!(buf.head_offset(), 8);
    assert_eq!(buf.tail_offset(), 0);

    // Now write 4 ASCII bytes: b"ABCD"
    // Total head = 12. Capacity = 10.
    // Raw tail candidate = 12 - 10 = 2 (which is 'l' in "hello", ASCII).
    buf.write(b"ABCD");
    assert_eq!(buf.head_offset(), 12);
    assert_eq!(buf.tail_offset(), 2);

    // Now write 4 more ASCII bytes: b"EFGH"
    // Total head = 16. Capacity = 10.
    // Raw tail candidate = 16 - 10 = 6.
    // Offset 6 is 0xBA (continuation byte of 'ế')!
    // Offset 7 is 0xBF (continuation byte of 'ế')!
    // Offset 8 is 'A' (ASCII, lead byte).
    // Bounded UTF-8 alignment MUST skip offset 6 and offset 7, setting tail_offset = 8!
    buf.write(b"EFGH");
    assert_eq!(buf.head_offset(), 16);
    assert_eq!(buf.tail_offset(), 8);

    let slice = buf.read_slice(buf.tail_offset());
    assert_eq!(slice.start_offset, 8);
    assert_eq!(slice.end_offset, 16);
    assert_eq!(slice.data, b"ABCDEFGH".to_vec());
    // Assert slice is valid UTF-8
    assert!(std::str::from_utf8(&slice.data).is_ok());
}

#[test]
fn test_binary_data_resilience() {
    let mut buf = Utf8RingBuffer::new(10);
    // Write 20 continuation bytes (0x80)
    let binary = vec![0x80u8; 20];
    buf.write(&binary);

    assert_eq!(buf.head_offset(), 20);
    // Raw candidate: 20 - 10 = 10.
    // Max skip is min(3, ...), so tail_offset must be at most 10 + 3 = 13.
    // It MUST NOT advance across the whole buffer up to 20!
    assert!(buf.tail_offset() <= 13);
    assert!(buf.tail_offset() >= 10);
    assert!(!buf.is_empty());
}

#[test]
fn test_underrun_detection() {
    let mut buf = Utf8RingBuffer::new(10);
    buf.write(b"0123456789abcdefghij"); // 20 bytes

    assert_eq!(buf.head_offset(), 20);
    assert_eq!(buf.tail_offset(), 10);

    // Client requests from offset 0, which was evicted
    let slice = buf.read_slice(0);
    assert!(slice.underrun);
    assert_eq!(slice.start_offset, 10);
    assert_eq!(slice.end_offset, 20);
    assert_eq!(slice.data, b"abcdefghij".to_vec());
}

#[test]
fn test_future_offset_and_empty() {
    let mut buf = Utf8RingBuffer::new(32);
    let slice = buf.read_slice(0);
    assert_eq!(slice.start_offset, 0);
    assert_eq!(slice.end_offset, 0);
    assert!(slice.data.is_empty());
    assert!(!slice.underrun);

    buf.write(b"data");
    let future_slice = buf.read_slice(100);
    assert_eq!(future_slice.start_offset, 4);
    assert_eq!(future_slice.end_offset, 4);
    assert!(future_slice.data.is_empty());
    assert!(!future_slice.underrun);
}

#[test]
fn default_capacity_is_4_mib() {
    assert_eq!(DEFAULT_RING_BUFFER_CAPACITY, 4 * 1024 * 1024);
}

#[test]
fn write_crossing_capacity_during_growth_keeps_newest_bytes() {
    let mut ring = Utf8RingBuffer::new(8);
    ring.write(b"abcdef");
    ring.write(b"ghij");
    let slice = ring.read_slice(0);
    assert!(slice.underrun);
    assert_eq!(slice.data, b"cdefghij");
    assert_eq!(slice.start_offset, 2);
    assert_eq!(slice.end_offset, 10);
}

#[test]
fn single_write_larger_than_capacity_keeps_tail() {
    let mut ring = Utf8RingBuffer::new(8);
    ring.write(b"0123456789abcdefghij");
    let slice = ring.read_slice(0);
    assert_eq!(slice.data, b"cdefghij");
    assert_eq!(slice.start_offset, 12);
    assert_eq!(slice.end_offset, 20);
}
