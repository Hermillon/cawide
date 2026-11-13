//! End-to-end integration tests for RPC response compression over loopback QUIC.

mod common;

use cawide_protocol::{
    read_rpc_response, write_rpc_request, write_rpc_request_with_caps, RpcRequest, RpcResponse,
    StreamPurpose, RPC_CAP_ZSTD, RPC_FLAG_COMPRESSED,
};
use common::{open, within, Env};

#[tokio::test(flavor = "multi_thread")]
async fn test_rpc_loopback_compression() {
    let env = Env::start().await;

    // Create a 200 KiB repetitive text file in the workspace
    let single_line = "The quick brown fox jumps over the lazy dog 1234567890.\n";
    let repeat_count = (200 * 1024) / single_line.len() + 1;
    let text_content = single_line.repeat(repeat_count);
    env.write("large_text.txt", text_content.as_bytes());

    let req = RpcRequest::FsRead {
        root: env.root(),
        path: "large_text.txt".to_string(),
        offset: 0,
        length: text_content.len() as u32,
    };

    // 1. Caps-advertising request (RPC_CAP_ZSTD):
    // Open a new RPC stream on the QUIC connection
    let (mut send_caps, mut recv_caps) = open(&env.conn, StreamPurpose::Rpc).await;
    within(write_rpc_request_with_caps(
        &mut send_caps,
        101,
        &req,
        RPC_CAP_ZSTD,
    ))
    .await
    .unwrap();

    // Inspect the raw 8-byte header from the server to check bit 31
    let mut header_caps = [0u8; 8];
    within(recv_caps.read_exact(&mut header_caps))
        .await
        .unwrap();
    let resp_id_caps = u32::from_be_bytes([
        header_caps[0],
        header_caps[1],
        header_caps[2],
        header_caps[3],
    ]);
    let raw_len_caps = u32::from_be_bytes([
        header_caps[4],
        header_caps[5],
        header_caps[6],
        header_caps[7],
    ]);
    assert_eq!(resp_id_caps, 101);
    assert_ne!(
        raw_len_caps & RPC_FLAG_COMPRESSED,
        0,
        "Bit 31 must be set on the length field for compressed response"
    );

    // Read the rest of the compressed frame and decode through read_rpc_response
    let masked_len = (raw_len_caps & !RPC_FLAG_COMPRESSED) as usize;
    let mut payload_buf = vec![0u8; masked_len];
    within(recv_caps.read_exact(&mut payload_buf))
        .await
        .unwrap();

    // Reconstruct the full frame buffer to verify read_rpc_response decodes it properly
    let mut full_frame = Vec::with_capacity(8 + masked_len);
    full_frame.extend_from_slice(&header_caps);
    full_frame.extend_from_slice(&payload_buf);
    let mut cursor = std::io::Cursor::new(full_frame);
    let decoded = within(read_rpc_response(&mut cursor))
        .await
        .unwrap()
        .expect("decoded frame");
    assert_eq!(decoded.request_id, 101);
    match decoded.payload {
        RpcResponse::FsRead(Ok(res)) => {
            assert_eq!(res.data, text_content.as_bytes());
            assert_eq!(res.total_size, text_content.len() as u64);
        }
        other => panic!("expected FsRead result, got {:?}", other),
    }

    // 2. Legacy request (caps == 0 via write_rpc_request):
    let (mut send_legacy, mut recv_legacy) = open(&env.conn, StreamPurpose::Rpc).await;
    within(write_rpc_request(&mut send_legacy, 102, &req))
        .await
        .unwrap();

    // Inspect the raw 8-byte header from the server to check bit 31 is clear
    let mut header_legacy = [0u8; 8];
    within(recv_legacy.read_exact(&mut header_legacy))
        .await
        .unwrap();
    let resp_id_legacy = u32::from_be_bytes([
        header_legacy[0],
        header_legacy[1],
        header_legacy[2],
        header_legacy[3],
    ]);
    let raw_len_legacy = u32::from_be_bytes([
        header_legacy[4],
        header_legacy[5],
        header_legacy[6],
        header_legacy[7],
    ]);
    assert_eq!(resp_id_legacy, 102);
    assert_eq!(
        raw_len_legacy & RPC_FLAG_COMPRESSED,
        0,
        "Bit 31 must be clear for legacy request"
    );

    // Read remaining payload and verify content
    let legacy_len = raw_len_legacy as usize;
    let mut legacy_payload = vec![0u8; legacy_len];
    within(recv_legacy.read_exact(&mut legacy_payload))
        .await
        .unwrap();

    let mut full_legacy = Vec::with_capacity(8 + legacy_len);
    full_legacy.extend_from_slice(&header_legacy);
    full_legacy.extend_from_slice(&legacy_payload);
    let mut cursor = std::io::Cursor::new(full_legacy);
    let decoded_legacy = within(read_rpc_response(&mut cursor))
        .await
        .unwrap()
        .expect("decoded frame");
    assert_eq!(decoded_legacy.request_id, 102);
    match decoded_legacy.payload {
        RpcResponse::FsRead(Ok(res)) => {
            assert_eq!(res.data, text_content.as_bytes());
            assert_eq!(res.total_size, text_content.len() as u64);
        }
        other => panic!("expected FsRead result, got {:?}", other),
    }
}
