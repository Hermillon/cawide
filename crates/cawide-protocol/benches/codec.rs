use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::io::Cursor;

use cawide_protocol::codec::{
    encode_rpc_response_frame, read_control_message, read_pty_attach_header, read_rpc_response,
    write_control_message, write_pty_attach_header, write_rpc_response,
    write_rpc_response_with_caps, RPC_CAP_ZSTD,
};
use cawide_protocol::types::{
    ControlMessage, DiffHunk, DiffLine, DiffLineKind, FsChunk, GitFileDiff, GitReply,
    PtyAttachHeader, RpcResponse,
};

fn bench_codec(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // 1. Ping
    let ping = ControlMessage::Ping {
        client_ts: 1_234_567_890,
    };
    let mut ping_bytes = Vec::new();
    rt.block_on(async {
        write_control_message(&mut ping_bytes, &ping)
            .await
            .expect("encode ping");
    });

    let mut group = c.benchmark_group("codec_ping");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(32);
                write_control_message(&mut buf, black_box(&ping))
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&ping_bytes[..]));
                let _ = read_control_message(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    // 2. 200 KB GitDiff Response
    let line = DiffLine {
        kind: DiffLineKind::Context,
        content: "x".repeat(100),
    };
    let hunk = DiffHunk {
        file_path: "src/main.rs".into(),
        old_start: 1,
        old_lines: 100,
        new_start: 1,
        new_lines: 100,
        header: "@@ -1,100 +1,100 @@".into(),
        lines: vec![line; 100],
        content_hash: "abcd".into(),
    };
    let diff_resp = RpcResponse::Git {
        result: Ok(GitReply::Diff {
            diff: GitFileDiff {
                path: "src/main.rs".into(),
                old_path: None,
                binary: false,
                too_large: false,
                lfs: false,
                total_bytes: 200 * 1024,
                hunks: vec![hunk; 20],
            },
        }),
    };
    let mut diff_bytes = Vec::new();
    rt.block_on(async {
        write_rpc_response(&mut diff_bytes, 1, &diff_resp)
            .await
            .expect("encode diff");
    });

    let mut group = c.benchmark_group("codec_git_diff_200kb");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(diff_bytes.len());
                write_rpc_response(&mut buf, 1, black_box(&diff_resp))
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&diff_bytes[..]));
                let _ = read_rpc_response(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    let mut diff_compressed_bytes = Vec::new();
    rt.block_on(async {
        write_rpc_response_with_caps(&mut diff_compressed_bytes, 1, &diff_resp, RPC_CAP_ZSTD)
            .await
            .expect("encode compressed diff");
    });

    let mut group = c.benchmark_group("codec_git_diff_200kb_compressed");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(diff_compressed_bytes.len());
                write_rpc_response_with_caps(&mut buf, 1, black_box(&diff_resp), RPC_CAP_ZSTD)
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&diff_compressed_bytes[..]));
                let _ = read_rpc_response(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    // 3. 2 KB Attach Header
    let attach_header = PtyAttachHeader::new("a".repeat(2000), 1024, false);
    let mut attach_bytes = Vec::new();
    rt.block_on(async {
        write_pty_attach_header(&mut attach_bytes, &attach_header)
            .await
            .expect("encode attach header");
    });

    let mut group = c.benchmark_group("codec_attach_header_2kb");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(attach_bytes.len());
                write_pty_attach_header(&mut buf, black_box(&attach_header))
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&attach_bytes[..]));
                let _ = read_pty_attach_header(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    // 4. 1 MiB source-text FsReadChunk Response
    let source_line =
        "pub fn calculate_metrics(data: &[f64]) -> Result<Summary, Error> {\n    // process loop\n";
    let chunk_repeat = (1024 * 1024) / source_line.len() + 1;
    let chunk_data = source_line.repeat(chunk_repeat).into_bytes();
    let chunk_resp = RpcResponse::FsReadChunk(Ok(FsChunk {
        data: chunk_data,
        too_large: false,
        total_size: 1024 * 1024,
        modified_unix_ns: 0,
    }));
    let mut chunk_bytes = Vec::new();
    rt.block_on(async {
        write_rpc_response(&mut chunk_bytes, 1, &chunk_resp)
            .await
            .expect("encode chunk");
    });

    let mut group = c.benchmark_group("codec_fs_read_chunk_1mb");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(chunk_bytes.len());
                write_rpc_response(&mut buf, 1, black_box(&chunk_resp))
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&chunk_bytes[..]));
                let _ = read_rpc_response(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    let mut chunk_compressed_bytes = Vec::new();
    rt.block_on(async {
        write_rpc_response_with_caps(&mut chunk_compressed_bytes, 1, &chunk_resp, RPC_CAP_ZSTD)
            .await
            .expect("encode compressed chunk");
    });

    let mut group = c.benchmark_group("codec_fs_read_chunk_1mb_compressed");
    group.bench_function("encode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut buf = Vec::with_capacity(chunk_compressed_bytes.len());
                write_rpc_response_with_caps(&mut buf, 1, black_box(&chunk_resp), RPC_CAP_ZSTD)
                    .await
                    .expect("encode");
            });
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cursor = Cursor::new(black_box(&chunk_compressed_bytes[..]));
                let _ = read_rpc_response(&mut cursor).await.expect("decode");
            });
        });
    });
    group.finish();

    let mut group = c.benchmark_group("rpc_encode_fs_read_chunk_1mib");
    group.bench_function("encode", |b| {
        b.iter(|| {
            let _ = encode_rpc_response_frame(1, black_box(&chunk_resp), 0).expect("encode");
        });
    });
    group.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
