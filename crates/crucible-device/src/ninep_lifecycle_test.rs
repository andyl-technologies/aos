//! 9p lifecycle, restore, latency, and structured-fuzz tests.

use std::collections::BTreeMap;

use super::test_support::*;
use super::*;
use crate::subnode::IoCore;

#[test]
fn snapshot_restore_round_trips_fid_table_and_msize() {
    let mut dev = device();
    round_trip(&mut dev, 0, &tversion(1, 4096, codec::PROTOCOL_VERSION));
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &twalk(3, 1, 2, &["bin"]));
    let snap = dev.snapshot();
    assert_eq!(snap.server.msize, 4096);
    // The fid table holds both fid 1 (root) and fid 2 (bin).
    let fids: Vec<u32> = snap.fids().iter().map(|(f, _)| *f).collect();
    assert_eq!(fids, vec![1, 2]);

    // Restore over a freshly built (content-identical) tree.
    let restored = ok(NinepDevice::restore(&snap, sample_tree()));
    assert_eq!(restored.server().msize(), 4096);
    assert_eq!(restored.server().fids(), dev.server().fids());

    // The restored device answers a getattr on the restored fid identically.
    let mut a = dev;
    let mut b = restored;
    let (_, ra) = round_trip(&mut a, 10, &tgetattr(50, 2, 0x7ff));
    let (_, rb) = round_trip(&mut b, 10, &tgetattr(50, 2, 0x7ff));
    assert_eq!(ra, rb, "restored fid table must answer identically");
}

#[test]
fn snapshot_preserves_inflight_responses() {
    let mut dev = device();
    // Submit without advancing: the reply stays in flight.
    ok(dev.submit(0, &tversion(1, 4096, codec::PROTOCOL_VERSION)));
    assert_eq!(dev.core().inflight_len(), 1);
    let snap = dev.snapshot();
    assert_eq!(snap.inflight().len(), 1);
    let restored = ok(NinepDevice::restore(&snap, sample_tree()));
    assert_eq!(restored.core().inflight_len(), 1);
    assert_eq!(
        restored.core().next_exact_local_event(),
        dev.core().next_exact_local_event()
    );
}

// ---- completion model + determinism (IO-22, IO-28) -------------------

/// Drives a fixed request sequence and returns (delivery_icount, reply) of
/// every response. `skew` is artificial host work that must NOT affect output.
fn run_sequence(skew: usize) -> Vec<(u64, Vec<u8>)> {
    let mut dev = device();
    let reqs = vec![
        tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        tattach(2, 1),
        twalk(3, 1, 2, &["bin", "tool"]),
        tlopen(4, 2, 0),
        tread(5, 2, 0, 64),
        tgetattr(6, 2, 0x7ff),
        tclunk(7, 2),
    ];
    let mut out = Vec::new();
    let mut t = 0u64;
    for req in &reqs {
        let mut sink = 0u64;
        for i in 0..skew {
            sink = sink.wrapping_add(i as u64);
        }
        std::hint::black_box(sink);

        ok(dev.submit(t, req));
        let lim = dev.core().next_exact_local_event().unwrap_or(t);
        ok(dev.advance_to(lim));
        while let Some(pending) = dev.core_mut().pop_response() {
            out.push((pending.delivery_icount(), pending.response.payload));
        }
        t = lim;
    }
    out
}

#[test]
fn completion_is_host_timing_independent() {
    let a = run_sequence(0);
    let b = run_sequence(500_000);
    assert_eq!(a, b, "host COMPUTE skew leaked into delivery/payload");
}

#[test]
fn run_twice_is_byte_identical() {
    let first = run_sequence(0);
    let second = run_sequence(0);
    assert_eq!(first, second);
}

#[test]
fn latency_depends_only_on_message_kind_and_size() {
    let lat = NinepLatency::new(800, 1200, 2);
    let read = tread(1, 1, 0, 64);
    let clunk = tclunk(1, 1);
    // A read uses the data floor; a clunk uses the control floor.
    assert_eq!(lat.latency_for(&read), 1200 + 2 * read.len() as u64);
    assert_eq!(lat.latency_for(&clunk), 800 + 2 * clunk.len() as u64);
    // A garbage frame falls back to the control floor.
    assert_eq!(lat.latency_for(&[0xFF]), 800 + 2);
}

// ---- arbitrary-bytes decoder never panics (IO-18) --------------------

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    // A deterministic LCG fuzz over Message::decode and the server handler:
    // arbitrary bytes in, never a panic / OOB read, always Ok or a codec
    // error, and the SERVER always produces a well-formed reply frame.
    let mut state: u64 = 0x0bad_f00d_dead_beef;
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    let mut t = 1u64;
    for _ in 0..50_000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (state >> 56) as usize % 48;
        let mut bytes = Vec::with_capacity(len);
        let mut s = state;
        for _ in 0..len {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((s >> 33) as u8);
        }
        // The decoder never panics.
        let _ = Message::decode(&bytes);
        // The server never panics and always yields a valid 9p reply frame
        // (size prefix matches length) — even for hostile bytes.
        if let Ok(reply) = dev.server().clone().handle(&bytes) {
            assert!(reply.len() >= codec::HEADER_LEN);
            let size = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
            assert_eq!(size, reply.len(), "reply size prefix must match length");
        }
        // Also exercise the real submit path occasionally (bounded frames).
        if len >= codec::HEADER_LEN && bytes.len() <= dev.server().msize() as usize {
            // Fix the size prefix so the frame is structurally plausible.
            let size = bytes.len() as u32;
            bytes[0..4].copy_from_slice(&size.to_le_bytes());
            if dev.submit(t, &bytes).is_ok() {
                let lim = dev.core().next_exact_local_event().unwrap_or(t);
                let _ = dev.advance_to(lim);
                while dev.core_mut().pop_response().is_some() {}
                t = lim;
            }
        }
    }
}

#[test]
fn structured_fuzz_reaches_deep_decode_paths_without_panic() {
    // The shallow random-bytes fuzz above almost always bails at the
    // size-prefix check, so the doc-advertised adversarial shapes (huge
    // string/name lengths, nwname=0xFFFF, count=u32::MAX, valid bodies of
    // every type) are never reached. This fuzzer emits WELL-FRAMED messages
    // (correct size prefix) with a chosen type byte and adversarial field
    // values, so the body decoders and the server handlers are exercised on
    // hostile-but-plausible input. The invariant is the same: never panic,
    // and the server always yields a well-formed reply whose size prefix
    // matches its length and whose length is within msize.
    let mut state: u64 = 0xfeed_face_c0ff_ee00;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    // The full set of 9p type bytes the dispatcher recognizes, plus a couple
    // of unknowns, so every match arm is reachable.
    let types: [u8; 18] = [
        codec::TVERSION,
        codec::TATTACH,
        codec::TWALK,
        codec::TLOPEN,
        codec::TREAD,
        codec::TREADDIR,
        codec::TGETATTR,
        codec::TREADLINK,
        codec::TSTATFS,
        codec::TCLUNK,
        codec::TFLUSH,
        codec::TXATTRWALK,
        codec::TFSYNC,
        codec::TWRITE, // mutating
        codec::TMKDIR, // mutating
        200,           // unknown
        7,             // Rlerror-as-request (unknown direction)
        0,             // type 0
    ];

    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    let msize = dev.server().msize() as usize;
    let mut t = 2u64;

    for _ in 0..40_000 {
        let r = next();
        let msg_type = types[(r >> 3) as usize % types.len()];
        let tag = (r >> 11) as u16;

        // Build an adversarial body: a mix of valid-shaped fields with
        // extreme values (max counts, oversized declared string lengths).
        let mut body: Vec<u8> = Vec::new();
        // fid / newfid words drawn from a tiny set incl. the live fids 1/2.
        let fid = [0u32, 1, 2, u32::MAX][(r >> 17) as usize % 4];
        body.extend_from_slice(&fid.to_le_bytes());

        match (r >> 19) % 6 {
            0 => {
                // A second fid + an oversized declared string length.
                body.extend_from_slice(&2u32.to_le_bytes());
                body.extend_from_slice(&u16::MAX.to_le_bytes()); // declared len
                body.extend_from_slice(b"short"); // far fewer bytes than declared
            }
            1 => {
                // offset + count=u32::MAX (Tread/Treaddir shape).
                body.extend_from_slice(&(r).to_le_bytes()); // offset (8)
                body.extend_from_slice(&u32::MAX.to_le_bytes()); // count
            }
            2 => {
                // Twalk with nwname=0xFFFF but only a couple of names present.
                body.extend_from_slice(&3u32.to_le_bytes()); // newfid
                body.extend_from_slice(&u16::MAX.to_le_bytes()); // nwname
                body.extend_from_slice(&string_bytes("a"));
                body.extend_from_slice(&string_bytes("b"));
            }
            3 => {
                // request_mask / flags (8 bytes of entropy).
                body.extend_from_slice(&r.to_le_bytes());
            }
            4 => {
                // A long, valid-length name (exercises near-namelen entries).
                let name = "z".repeat((r as usize) % 300);
                body.extend_from_slice(&3u32.to_le_bytes());
                body.extend_from_slice(&1u16.to_le_bytes()); // nwname = 1
                body.extend_from_slice(&string_bytes(&name));
            }
            _ => {
                // A grab-bag of random trailing bytes.
                let n = (r as usize) % 64;
                let mut s = r;
                for _ in 0..n {
                    s = s.wrapping_mul(2862933555777941757).wrapping_add(1);
                    body.push((s >> 40) as u8);
                }
            }
        }

        let f = frame(msg_type, tag, &body);
        // The decoder never panics on this well-framed-but-hostile input.
        let _ = Message::decode(&f);
        // The server never panics and always yields a valid, within-msize
        // reply frame whose size prefix matches its length.
        let reply = dev
            .server()
            .clone()
            .handle(&f)
            .unwrap_or_else(|e| panic!("handle returned Err on structured input: {e}"));
        assert!(reply.len() >= codec::HEADER_LEN);
        let size = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
        assert_eq!(size, reply.len(), "reply size prefix must match length");
        assert!(
            reply.len() <= msize,
            "reply exceeded msize: type {msg_type} -> {} bytes",
            reply.len()
        );

        // Drive the real lifecycle for in-msize frames.
        if f.len() <= msize && dev.submit(t, &f).is_ok() {
            let lim = dev.core().next_exact_local_event().unwrap_or(t);
            let _ = dev.advance_to(lim);
            while dev.core_mut().pop_response().is_some() {}
            t = lim;
        }
    }
}

// ---- signal-driven exact request directives -------------------------
