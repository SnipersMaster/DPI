# DPI engine — reference implementation

A Linux, C-based deep packet inspection engine: raw traffic capture,
RFC-conformant IPv4/TCP parsing, TLS SNI extraction, app-category
classification, DGA scoring, VPN/tunnel detection, and a pluggable
dissector registry with RADIUS and QUIC modules.

**Status: reference architecture, not a finished product.** Every file
was written and reviewed for structural correctness, but none of it has
been compiled or run against live traffic — this development sandbox
has no NIC, no DPDK, no libseccomp/libssl dev headers, and no network
access. Treat this as a detailed starting point to build and validate
in your own lab, not something to point at production traffic as-is.
See the per-file status table below before trusting any specific piece.

## Architecture

```
                    ┌─────────────────────────┐
                    │   dpi_secure_bootstrap.c │  single-core reference:
                    │   or dpi_dpdk_worker.c   │  privilege drop, seccomp,
                    │   (capture entry point)  │  raw socket / DPDK RX
                    └────────────┬─────────────┘
                                 │ raw packet bytes
                                 ▼
                    ┌─────────────────────────┐
                    │    dpi_rfc_parser.c      │  IPv4 (RFC 791) + TCP
                    │  (per-segment L3/L4      │  (RFC 9293), checksums,
                    │   dissection)            │  options, fragmentation
                    └────────────┬─────────────┘
                                 │ one TCP segment's payload
                                 ▼
                    ┌─────────────────────────┐
                    │ dpi_tcp_flow_reassembly.c│  per-flow reassembly,
                    │  (stream reassembly)     │  overlap-resolution
                    │                          │  policy, evasion detection
                    └────────────┬─────────────┘
                                 │ contiguous, in-order bytes
                                 │ (only on each flow's first delivery —
                                 │  see is_first_delivery gating)
                                 ▼
        ┌────────────────────────────────────────────────┐
        │              dpi_app_classifier.c                │
        │  orchestrates: SNI extraction, domain lookup,     │
        │  DGA scoring, VPN scoring, DoH/DoT scoring —       │
        │  produces one flow record per connection           │
        └───┬──────────┬──────────────┬─────────────────┬──┘
            │           │              │                 │
            ▼           ▼              ▼                 ▼
  dpi_domain_rules_  dpi_dga_       dpi_vpn_        dpi_doh_dot_
  loader.c           detector.c    detector.c       detector.c
  (reads             (lexical      (protocol/port/  (port+TLS shape
  domain_rules.ini,  scoring on    entropy scoring) for DoT, SNI-list
  hot-reloadable)    the SNI)                        match for DoH)

  Separately, `dpi_dissector_registry.c` + `dpi_radius_parser.c` +
  `dpi_quic_parser.c` handle UDP-based protocols (RADIUS, QUIC) via a
  pluggable detect()/dissect() interface, plus `dpi_vpn_detector.c` for
  WireGuard/IKE fingerprinting. **This UDP path is now wired into both
  capture files too** — it skips flow reassembly entirely (UDP is
  datagram-oriented, nothing to reassemble across packets) and calls
  `dispatch_dissection()` directly per datagram.
```

**Both diagrams above now reflect actual wiring, not just intended architecture** — both capture entry points genuinely call the full chain for TCP (RFC parser → flow reassembly → classifier) and UDP (RFC parser → dissector registry + VPN fingerprinting) as of this pass. DoT is TCP-based (RFC 7858), so it's covered by the TCP branch, not the UDP one — worth being precise about that distinction since it's easy to lump all "DNS-adjacent encrypted" protocols together.

## Supported protocols

Three tiers, and the distinction matters: "parsed" means structured
fields are extracted and validated; "detected" means the engine can
recognize/score the traffic but doesn't extract protocol fields;
everything else is not touched by this engine at all yet.

### Fully parsed (structured fields extracted)

| Protocol | RFC | File | What's extracted |
|---|---|---|---|
| Ethernet | IEEE 802.3 | `dpi_secure_bootstrap.c` / `dpi_dpdk_worker.c` | Ethertype, basic frame bounds. No VLAN (802.1Q) tag handling yet. |
| IPv4 | RFC 791 | `dpi_rfc_parser.c` | Header checksum validation, options (TLV), fragmentation reassembly (see gaps below) |
| TCP | RFC 9293 | `dpi_rfc_parser.c` | Checksum validation, options (MSS, window scale, SACK-permitted, timestamps). Per-flow overlap-resolution policy not yet implemented (see gaps below). |
| TLS (ClientHello / SNI) | RFC 8446, RFC 6066 | `dpi_app_classifier.c` | SNI hostname from the ClientHello `server_name` extension. Does not parse the rest of the handshake (cipher suites, other extensions, certificates). |
| RADIUS | RFC 2865, RFC 2866 | `dpi_radius_parser.c` | Packet code, identifier, User-Name, NAS-IP-Address, Calling-Station-ID, Acct-Status-Type. `User-Password` is detected as present but its value is deliberately never extracted (credential handling). |
| DNS-over-TLS (DoT) | RFC 7858 | `dpi_doh_dot_detector.c` | Structural detection: port 853 + TLS ClientHello shape. Genuine structural signal, same discipline as the VPN detector. |

### Detected / scored, not fully dissected

| Protocol | File | What it does |
|---|---|---|
| QUIC | `dpi_quic_parser.c` | RFC 9000/9001: identifies Initial packets, derives keys, removes header protection, AEAD-decrypts the payload, locates the CRYPTO frame, and now extracts SNI from the enclosed ClientHello (wired to `extract_sni_from_clienthello_body()`, which was split out of the TLS-over-TCP SNI parser specifically because QUIC's CRYPTO frame has no TLS record-layer wrapper — RFC 9001 S4.1.3). Logic cross-checked against RFC 9001's own pseudocode line-by-line; **not yet validated against RFC 9001 Appendix A.2's byte-exact test vectors** — those are two different levels of confidence, see the file header. |
| DNS-over-HTTPS (DoH) | `dpi_doh_dot_detector.c` | No structural fingerprint exists — DoH is indistinguishable from ordinary HTTPS at the wire level. Detection is entirely SNI-based, matching against `domain_rules.ini`'s `[dns_over_https]` category. This is stated plainly rather than implying a cleverer detection method exists. |
| WireGuard | `dpi_vpn_detector.c` | Fingerprints handshake message types/sizes to produce a VPN-likelihood score. Does not parse WireGuard's actual handshake cryptographic fields or transport data. |
| OpenVPN | `dpi_vpn_detector.c` | Recognizes the opcode byte pattern for a VPN-likelihood score. No further field extraction. |
| IKE / IPsec (IKEv1/IKEv2) | `dpi_vpn_detector.c` | Validates the ISAKMP header shape and version for a VPN-likelihood score. No payload/SA parsing. |
| Encrypted Client Hello (ECH) | `dpi_app_classifier.c` | Recognized only as "SNI absent, TLS 1.3 handshake" — not decoded (ECH decoding would require the ECH config's private key, which a network observer doesn't have by design). |

### Not supported yet

Everything else. Notably absent, roughly in order of likely value if
you extend this: **IPv6** (the entire engine is IPv4-only right now —
this is a significant gap, not a minor one, given IPv6 traffic share),
**DNS** (high value — cheap to add, plaintext unless DoH/DoT, and
useful both standalone and as a correlation signal for the DGA/VPN
detectors), **HTTP/1.1 and HTTP/2** (Host header / `:authority`
extraction, useful where TLS isn't in play or as a fallback), **SSH**,
**FTP**, **SMTP/IMAP/POP3**, **SMB**, **SIP/RTP**, **MQTT**, **NTP**,
**DHCP**, **SNMP**, and industrial/ICS protocols (Modbus, DNP3) if
that's relevant to your deployment. All of these would plug into
`dpi_dissector_registry.c` following the same `detect()`/`dissect()`
pattern already used for RADIUS and QUIC — that registry is what makes
adding each of these an isolated, independently-fuzzable module rather
than a growing special case inside one function.



| File | Role | Depends on |
|---|---|---|
| `dpi_secure_bootstrap.c` | Single-core reference capture loop: opens raw `AF_PACKET` socket as root, drops privileges, installs a seccomp filter. **Wired end-to-end for both TCP and UDP**: TCP → flow reassembly → classification; UDP → RADIUS/QUIC dissector registry + VPN fingerprinting, no reassembly (datagram-oriented). Prints one JSON record per flow/datagram to stdout — fine at this scale. Good starting point for lab testing at low traffic rates. | libseccomp, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC |
| `dpi_dpdk_worker.c` | Multi-core, DPDK-based capture worker for 100G line rate. RSS across cores, VFIO-based device binding (IOMMU-protected DMA). **Wired end-to-end for both TCP and UDP**, with 100G-specific care: classification gated to run once per flow (`is_first_delivery`), mbuf freed before classification runs, and output goes through `dpi_async_output.c`'s lock-free ring buffer — no blocking I/O on the hot path. Contains detailed lab setup instructions in its header comment (IOMMU, hugepages, core isolation) — read those before the code. | DPDK, VFIO-capable NIC/kernel, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC, async output |
| `dpi_async_output.c` | Lock-free per-lcore SPSC ring buffer + dedicated drain pthread, replacing the DPDK worker's earlier hot-path `printf()`. Producers (lcores) never block — a full ring drops and counts, never stalls. Formatting/I/O happens only in the drain thread. Deliberately a plain pthread, not another DPDK lcore, since it does blocking I/O and shouldn't consume an isolated poll-mode core. | none (self-contained) |
| `dpi_rfc_parser.c` | RFC-conformant IPv4 (RFC 791), TCP (RFC 9293), and now UDP (RFC 768) parsing: checksum verification, options parsing, IPv4 fragmentation reassembly. States an explicit open decision on TCP overlap-resolution policy (first-wins vs last-wins) rather than silently picking one — implemented in `dpi_tcp_flow_reassembly.c`, see below. | none (self-contained) |
| `dpi_tcp_flow_reassembly.c` | Per-flow TCP stream reassembly sitting on top of the per-segment parsing above. Implements the overlap-resolution policy (configurable FIRST_WINS/LAST_WINS) and, more importantly, detects the actual evasion-relevant case: overlapping segments whose bytes *disagree* at the same position (vs. benign identical retransmission). Timeout eviction + hard flow-count ceiling included. **Flow table is now partitioned per-lcore** (`partition_id` parameter) — an earlier version shared one global table across all lcores with no locking, a real data race caught while wiring this into the multi-core worker. Wired into both capture paths. Includes a test-only reset helper for the fuzz harness. | none (self-contained) |
| `fuzz_rfc_parser.c`, `fuzz_tcp_reassembly.c`, `fuzz_radius_parser.c`, `fuzz_quic_header.c`, `fuzz_quic_frames.c` | libFuzzer harnesses for the five highest-value fuzz targets. QUIC gets two harnesses split at its crypto boundary (see `FUZZING.md` for why). Reviewed but **not compiled or run** — no clang/libFuzzer toolchain available in this sandbox. | See `fuzz_build.sh` |
| `fuzz_build.sh` | Build commands for all five harnesses (libFuzzer + ASan/UBSan), plus an AFL++ alternative note. Not executed here. | clang, libssl-dev |
| `fuzz_seeds/` | A small, hand-verified seed corpus per harness — chosen to represent the cases that matter (e.g. the TCP reassembly seeds specifically cover in-order, benign-overlap, and conflicting-overlap cases), not just arbitrary valid packets. | none |
| `FUZZING.md` | Methodology (especially the QUIC crypto-boundary split), runtime/coverage expectations, and a crash triage checklist. | none |
| `dpi_app_classifier.c` | Orchestration layer. Extracts TLS SNI (RFC 8446 / RFC 6066), calls the domain classifier, DGA scorer, and VPN scorer, assembles one `app_classification` result per flow. | Includes the three files below directly |
| `dpi_domain_rules_loader.c` | Loads `domain_rules.ini` into a dynamic, hot-reloadable table. Validates entries on load (rejects paths/whitespace/malformed suffixes, flags duplicates) and logs a skip count. | `domain_rules.ini` |
| `domain_rules.ini` | ~420 domain→category rules across 20 categories (social media, streaming, messaging, cloud infra, productivity, e-commerce, gaming, finance, VPN providers, etc). Editable without a rebuild — reload is automatic on file change. | none |
| `dpi_dga_detector.c` | Lexical DGA (malware C2 domain) scoring: entropy, bigram likelihood, consonant runs, digit patterns → 0.0-1.0 score. | none (self-contained) |
| `dpi_vpn_detector.c` | VPN/tunnel scoring: WireGuard handshake fingerprint, OpenVPN opcode, IKE/ISAKMP header, known ports, SNI match against the `[vpn_proxy]` category, entropy fallback. | Reads `category` string produced by the domain classifier |
| `dpi_dissector_registry.c` | Pluggable protocol dissector framework: `detect()`/`dissect()` interface, confidence-based dispatch, port hints as tiebreaker only. This is the scalable path to adding more protocols. | none (framework only) |
| `dpi_radius_parser.c` | RADIUS (RFC 2865/2866) dissector: header + attribute TLVs. Deliberately never extracts `User-Password` value into output (credential handling). Fully structural, no crypto needed. | `dpi_dissector_registry.c` |
| `dpi_quic_parser.c` | QUIC (RFC 9000/9001) Initial packet dissector: HKDF key derivation (RFC 9001 §5.2, salt verified against the RFC), header protection removal, AES-128-GCM decryption. **Gets through decryption but SNI extraction is not yet wired up** — QUIC's CRYPTO frame has no TLS record-layer wrapper, so it needs a small refactor of `extract_sni()` before it can hand off to the existing SNI parser. See the TODO comment in the file. | OpenSSL (libssl/libcrypto) |

## Honest status per file — read before trusting any of it

| File | Compiled? | Tested against real data? | Known gaps |
|---|---|---|---|
| `dpi_secure_bootstrap.c` | No (missing dev headers in this sandbox) | No | Now includes 6 other files as one translation unit — a real compile is more likely to surface something here than before. `printf`-per-flow is fine at this scale. |
| `dpi_dpdk_worker.c` | No | No | Needs the IOMMU/VFIO/hugepage lab setup described in its header before it's even relevant. Now handles both TCP and UDP. Output goes through the async ring buffer, not a hot-path `printf()`. |
| `dpi_async_output.c` | No | No | ~52 MB static footprint at default sizing (documented in-file); drain thread sleeps 1ms when idle rather than busy-spinning — reasonable default, tune if your latency requirements differ |
| `dpi_rfc_parser.c` | No | No | Fragment reassembly cache still has no timeout eviction or memory ceiling (unlike the TCP flow reassembly layer, which does — this remains a real gap specific to the IPv4 fragment cache); TCP overlap-resolution policy is implemented in `dpi_tcp_flow_reassembly.c` |
| `dpi_tcp_flow_reassembly.c` | No | No | O(n) per-partition flow table scan (documented tradeoff); no hole-splitting for a segment landing fully inside an existing hole (documented gap, matches the IPv4 fragment reassembly's same limitation); **256 flows per lcore partition at default sizing (4096 total / 16 partitions)** — this is a real capacity ceiling per core, tune `TCP_REASSEMBLY_NUM_PARTITIONS`/`MAX_FLOWS` deliberately for your expected concurrent-flow count |
| `dpi_app_classifier.c` | No | No | JA3 fallback is stubbed, not implemented |
| `dpi_domain_rules_loader.c` | No | No | Reload swap is now a lock-free atomic pointer exchange with a bounded 4-slot grace-period retirement list (not full RCU/hazard pointers — appropriate for infrequent config-file reloads, not a general-purpose concurrent data structure pattern) |
| `domain_rules.ini` | N/A | No | Seed list from general knowledge, not live-verified; will have stale/missing entries. ~435 rules across 21 categories including `[dns_over_https]` |
| `dpi_dga_detector.c` | No | No | Weights are literature-informed starting points, not tuned against a labeled dataset |
| `dpi_vpn_detector.c` | No | No | Byte offsets for WireGuard/IKE unverified against real captures; largely blind to obfuscated/VPN-over-TLS traffic by design |
| `dpi_doh_dot_detector.c` | No | No | DoT structural detection unverified against real captures; DoH detection is inherently limited to SNI-list matching (no structural fallback exists) |
| `dpi_dissector_registry.c` | No | No | Framework only — O(n) dispatch noted as a possible future bottleneck at very high dissector counts |
| `dpi_radius_parser.c` | No | No | Otherwise structurally complete for the core RFC 2865 fields covered |
| `dpi_quic_parser.c` | No | No | SNI extraction wired end-to-end; logic cross-checked against RFC 9001 pseudocode but not run against the RFC's byte-exact test vectors; packet-number reconstruction is simplified (correct for a connection's first Initial packet only, see file header); no CRYPTO frame reassembly across multiple packets. **Fixed a real concurrency bug** while wiring into the multi-core worker: an earlier version used a `static` decryption buffer, which would have been silently corrupted by concurrent calls from different lcores — now stack-allocated. |

## Build order (once you have real dev headers and hardware)

```
# Prerequisites
sudo apt install libseccomp-dev libcap-dev libssl-dev
# DPDK: follow https://doc.dpdk.org/guides/linux_gsg/ for your kernel/NIC

# Single-core reference path (lab testing, low traffic)
gcc -O2 -Wall -Wextra -o dpi_bootstrap dpi_secure_bootstrap.c -lseccomp -lcap

# 100G path (requires DPDK + VFIO-bound NIC + hugepages configured first)
gcc -O3 -march=native $(pkg-config --cflags libdpdk) \
    -o dpi_dpdk_worker dpi_dpdk_worker.c $(pkg-config --libs libdpdk)

# QUIC module standalone test (once wired up)
gcc -O2 -Wall -o quic_test dpi_quic_parser.c -lssl -lcrypto
```

The RFC parser, classifier, domain loader, DGA/VPN detectors, and
dissector registry are currently structured as directly-`#include`d
translation units for simplicity (see the `#include "..."` lines inside
`dpi_app_classifier.c` and `dpi_dissector_registry.c`). For a real build
system, split these into proper headers + separately compiled `.o`
files — the `#include`-a-`.c`-file pattern used here is fine for a
reference/prototype stage but not for a maintained codebase.

## Suggested next steps, roughly in priority order

**Done in this pass**: five libFuzzer harnesses (`fuzz_rfc_parser.c`,
`fuzz_tcp_reassembly.c`, `fuzz_radius_parser.c`, `fuzz_quic_header.c`,
`fuzz_quic_frames.c`), a seed corpus per harness, a build script, and
`FUZZING.md` covering methodology and crash triage. **Not compiled or
run** — no clang/libFuzzer in this sandbox. This is the single most
important next step to actually do in your lab before anything here
touches real traffic.

1. **Actually run the fuzzers** (see above — this is now possible, not
   yet done). Start with a few CPU-hours per harness minimum; see
   `FUZZING.md` for what "done" looks like and how to triage anything
   found.
2. **Compile everything against real dev headers** and fix whatever
   the compiler catches that a read-through couldn't (this has never
   been through a compiler — that remains true for every file here).
3. **Validate the QUIC module against RFC 9001 Appendix A.2's published
   test vector.** The module's *logic* has been cross-checked against
   the RFC's own pseudocode section by section, but that is not the
   same as confirming it produces byte-exact correct output against a
   known input. (Note: this is a different kind of check than fuzzing —
   fuzzing finds crashes and memory-safety bugs, not protocol
   correctness against the spec's own numbers.)
4. **Load-test the async output ring buffer under realistic burst
   conditions** to see actual drop rates at `LOG_RING_SIZE=8192` per
   lcore, and tune the constant against your real traffic mix.
5. **Add IPv6 support.** Flagged in the protocol table above as the
   most significant coverage gap — the entire engine is IPv4-only
   right now.
6. **Validate `dpi_vpn_detector.c` and `dpi_doh_dot_detector.c`'s
   structural assumptions against real captures** (WireGuard, OpenVPN,
   IKE, DoT sessions) — same "logic reviewed, not yet tested" caveat
   as everything else here.
7. **Choose a real output sink for `dpi_async_output.c`'s drain
   thread** — it currently just `printf`s the same JSON shape as
   before, as a placeholder. A production deployment needs this to
   write to a file, syslog, or a message queue instead.
