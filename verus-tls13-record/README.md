# verus-tls13-record

`verus-tls13-record` is the bounded TLS 1.3 record and key-epoch engine used by
the pinned rustls 0.23.43 integration in this repository. Its production
decision functions are also the functions checked by Verus: proof attributes
are enabled only by the verifier and erase to ordinary Rust.

The verified claim is functional refinement of the pinned RFC 8446 and RFC
8449 record model. It assumes authenticated handshake milestones and traffic
secrets, plus the documented AEAD and HKDF primitive contracts. It does not
claim verified TLS, cryptographic security, constant-time execution, or
physical key erasure.

The public API has separate sender and receiver states, bounded incremental
input, typed limits and epochs, explicit provider contracts, and fail-closed
errors. The `aws_lc_rs` adapter lives in rustls and performs primitive
operations using the header, nonce, and plaintext chosen here.
