# Selected TLS 1.3 record engine

`verus-tls13-record` is a workspace member used by rustls 0.23.43's AWS-LC
TLS 1.3 path.  It is not a parallel record implementation: rustls calls the
same executable functions that the focused Verus check reads.

## Selected profile

The integration covers the TLS 1.3 AES-128-GCM/SHA-256,
AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 suites supplied by
`aws-lc-rs`.  It does not change rustls's TLS 1.2, ring, QUIC, certificate, or
socket interfaces.

The key schedule recognizes the exact AWS-LC AEAD and HKDF adapter objects for
the three selected suites. Only that adapter identity activates exact
TLSInnerPlaintext framing, protected outer-type checks, directional epoch
limits, and `ConnectionControl` lifecycle enforcement in rustls. A copied
suite remains selected only when it retains those same AWS-LC adapters; provider
usage bounds alone cannot enable the seam. Other providers continue through
rustls's compatibility record path; they are intentionally outside this
result's verified boundary.

The public configuration surface is `ClientConfig::record_size_limit` and
`ServerConfig::record_size_limit`.  A value of `Some(64..=16385)` advertises
RFC 8449's protected-record limit; `None` keeps the TLS 1.3 maximum.  The peer
advertisement limits local sends, while the local advertisement limits peer
sends.  The rustls fragmenter applies the peer limit before AEAD so a valid
large application write is fragmented instead of silently discarded.

## Executable core and seams

| Core operation | rustls selected-path seam |
| --- | --- |
| Header framing, bounded stream accumulation, and `finish` | `msgs::deframer` uses `classify_frame`; `StreamFramer` is available for fixed-capacity consumers. |
| TLSInnerPlaintext type, zero padding, and length limit | `crypto::aws_lc_rs::tls13` calls `encode_inner` before sealing and `decode_inner` after opening. |
| Exact protected AAD and nonce input | AWS-LC adapters use `protected_header`, `received_protected_header`, and `nonce`. |
| Per-direction sequence and provider use limits | `RecordLayer` uses one `TrafficEpoch` per direction and activates a fresh epoch at every traffic-secret change. |
| Handshake boundaries and KeyUpdate ordering | On the selected path, `CommonState` observes fixed-size handshake framing; TLS 1.3 key-schedule transitions call `ConnectionControl` before and after the old-key KeyUpdate record. |
| CCS and established alert lifecycle | The connection route checks plaintext CCS through `ConnectionControl`; after rustls has reached its application-data phase, selected alert and terminal record-layer state are fail-closed. |
| HKDF label bytes | TLS 1.3 key, IV, and traffic-update expansion goes through `encode_hkdf_label`. |

The checked record limits are intentionally conservative AWS-LC profile
limits.  A failed authenticated open terminally closes its epoch before any
later provider call; a failed seal does the same.  Outer type is checked before
an AEAD open (while retaining rustls's public `DecryptError` compatibility),
and a received protected header preserves its actual legacy version bytes as
authenticated AAD.  RFC 8446 permits receivers to ignore that legacy version
field; it is not normalized for authentication. The deframer permits that
legacy version only for ApplicationData while an active selected read epoch
exists. A selected write-only early-data epoch therefore cannot weaken normal
plaintext or non-selected inbound version validation. Rejected 0-RTT trial
decryption installs the same selected read epoch and provider limits as normal
TLS 1.3 decryption.

## RFC traceability

* RFC 8446 sections 5.1 and 5.2: framing ceiling, protected outer header,
  TLSInnerPlaintext content type, zero padding, and record number nonce.
* RFC 8446 section 4.4.4: KeyUpdate traffic-secret transition and ordering.
* RFC 8446 appendix B.4: TLS 1.3 AEAD usage-limit policy source; the selected
  AWS-LC limits are represented explicitly rather than inferred from a
  sequence counter.
* RFC 8449 sections 3 and 4: `record_size_limit` encoding and its directional
  send/receive interpretation.

## Verification and residual TCB

Run the exact staged verifier named by the evaluator evidence:

```text
timeout --foreground 300s /ssd1/sichangheagent/vl_artifacts/tlsrec_rerun_2/toolchain/verus-x86-linux/verus verus-tls13-record/src/lib.rs --crate-type lib --no-cheating
```

`verus_only` adds specifications without replacing runtime bodies.  The command
must finish with a zero-error result; it verifies the annotated framing, inner
plaintext, sequence/nonce, limits, and supporting proof obligations.  The
residual TCB is deliberately explicit: Verus itself and its standard library,
Rust compilation and unsafe-free adapter code, rustls handshake/state-machine
code outside the selected seam, all non-AWS-LC providers and TLS 1.2/QUIC,
`aws-lc-rs` and AWS-LC AEAD/HKDF primitives, the operating environment, and the
peer's authenticated inputs.  This crate does not claim to verify the
cryptographic implementation or all rustls protocol behavior.

Focused runtime checks are:

```text
cargo test -p verus-tls13-record
cargo test -p rustls --no-default-features --features aws_lc_rs,std --test unbuffered tls13_handshake
cargo test -p rustls --no-default-features --features aws_lc_rs,std --test unbuffered kernel_key_updates_tls13
cargo test -p rustls --no-default-features --features aws_lc_rs,std --test api tls13_record_size_limit_negotiates_directionally_and_fragments
```

The last test performs bidirectional data flow with 64/96-byte directional
limits for each of the three selected AWS-LC TLS 1.3 suites.
