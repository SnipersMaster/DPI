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

## Deployment requirements (100G path)

| Component | Recommendation | Why |
|---|---|---|
| NIC | Mellanox/NVIDIA ConnectX-6 Dx/7, or Intel E810 — with a mature DPDK PMD and SR-IOV/VFIO support | Matches `dpi_dpdk_worker.c`'s RSS + VFIO design directly |
| CPU | Modern Xeon Scalable or EPYC, 16+ cores, prioritize per-core clock over raw core count | DPI work is distributed per-flow across cores via RSS; per-core throughput matters more than total count beyond your queue requirement |
| Core allocation | Isolated cores (`isolcpus`/`nohz_full`) for RX/dissection lcores (matching `TCP_REASSEMBLY_NUM_PARTITIONS`, default 16) + one non-isolated core for the async output drain thread | Directly mirrors this project's architecture — the drain thread is deliberately NOT an isolated lcore, see `dpi_async_output.c` |
| RAM | 64–128GB, with 1G hugepages (not 2MB) | Covers DPDK mbuf pools, the ~76MB TCP flow table, ~52MB output rings, and reduces TLB pressure at these packet rates |
| IOMMU | VFIO-capable (Intel VT-d / AMD-Vi), enabled in BIOS + kernel | Hard requirement — this is the entire reason VFIO was chosen over UIO (DMA isolation), not optional |
| NUMA | Single-socket preferred, or pin NIC/memory/cores to one node on dual-socket | Cross-NUMA access is a classic silent DPDK throughput killer |
| PCIe | 4.0/5.0 x16 for the NIC | A 100G NIC needs ~12.5GB/s just for line-rate RX; an underprovisioned slot silently caps throughput |

This is a sizing starting point, not a guarantee — actual capacity depends heavily on average packet size, active dissector count, and TLS/QUIC traffic ratio (crypto-touching code costs more per packet than plaintext parsing).

## The protocol "arsenal" — one place to enable/disable dissectors

`protocols.ini` is now the single control point for which dissectors
are active — `register_all_dissectors()` no longer hardcodes that
decision; it reads this file once at startup (via
`dpi_protocol_config.c`) and only registers what's enabled. A protocol
not listed defaults to ON, so this file is for turning things off, not
an allowlist you have to keep in sync with every new dissector added.

```ini
radius = true
quic   = true
gtp    = true
gtpv2  = true
dns    = true
http1  = true
http2  = true
ssh    = true
dhcp   = true
sip    = true
rtp    = true
```

**Scope limit, stated plainly**: this is a startup-time config, not
hot-reloaded like `domain_rules.ini`. Dissector registration happens
once, before the RX loop begins, and the registry has no "unregister"
operation — restart the engine to pick up a change here. Making
registration itself dynamic (so protocols could be toggled at runtime)
is a reasonable future enhancement, not attempted in this pass.

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
| IPv6 | RFC 8200 | `dpi_ipv6_parser.c` | Fixed header, extension header chain walking (Hop-by-Hop, Routing, Fragment, Destination Options), bounded against adversarial chains — verified against a 20-header cyclic-looking chain. **UDP-over-IPv6 gets full treatment** (all UDP-based dissectors work identically); **TCP-over-IPv6 is parsed and checksum-verified but deliberately not wired into flow reassembly/classification yet** — see the file's header comment on why (`dpi_tcp_flow_reassembly.c`'s flow key is sized for IPv4 addresses only). |
| TCP | RFC 9293 | `dpi_rfc_parser.c` | Checksum validation, options (MSS, window scale, SACK-permitted, timestamps). Overlap-resolution policy implemented in `dpi_tcp_flow_reassembly.c`. |
| TLS (ClientHello / SNI) | RFC 8446, RFC 6066 | `dpi_app_classifier.c` | SNI hostname from the ClientHello `server_name` extension. Does not parse the rest of the handshake (cipher suites, other extensions, certificates). |
| HTTP/1.1 | RFC 9110-9112 | `dpi_http1_parser.c` | Request/status line, method, path, status code, Host and User-Agent headers. No chunked transfer-encoding reassembly or body parsing. |
| HTTP/2 | RFC 9113 | `dpi_http2_parser.c` | Connection preface, frame-level metadata (type, stream ID, length) — frame counts, RST_STREAM ratio (Rapid-Reset-style abuse signal). **HEADERS frame content is NOT decoded** — HPACK (RFC 7541) is a genuinely separate, stateful subsystem, explicitly out of scope, see the file's header comment. |
| SSH | RFC 4253 | `dpi_ssh_parser.c` | Identification string (protocol/software version), KEXINIT algorithm name-lists (kex, host key, encryption, MAC — 8 of the 10 defined lists). Nothing past key exchange (genuinely encrypted from there). |
| DHCP | RFC 2131/2132 | `dpi_dhcp_parser.c` | Message type, requested IP, hostname, vendor class identifier. |
| SIP | RFC 3261 | `dpi_sip_rtp_parser.c` | Request/status line, method, status code, Call-ID/From/To headers. |
| RTP | RFC 3550 | `dpi_sip_rtp_parser.c` | Payload type, sequence number, timestamp, SSRC, marker bit. No port hint (RTP has no registered port — negotiated per-call via SDP). |
| RADIUS | RFC 2865, RFC 2866 | `dpi_radius_parser.c` | Packet code, identifier, User-Name, NAS-IP-Address, Calling-Station-ID, Acct-Status-Type. `User-Password` is detected as present but its value is deliberately never extracted (credential handling). |
| DNS-over-TLS (DoT) | RFC 7858 | `dpi_doh_dot_detector.c` | Structural detection: port 853 + TLS ClientHello shape. Genuine structural signal, same discipline as the VPN detector. |
| GTP-U v1 | 3GPP TS 29.281 | `dpi_gtp_parser.c` | Message type, TEID, sequence number. **G-PDU inner IP packets are now recursively dissected** (IPv4 only, bounded to exactly one level of nesting — a nested GTP-in-GTP tunnel is detected and flagged, deliberately NOT recursed into further, since unbounded recursion driven by attacker-controlled tunnel depth is exactly the resource-exhaustion vector this project's first security checklist warned about). Inner TCP flows get single-packet SNI extraction (not full flow reassembly — a ClientHello split across multiple G-PDU packets won't be caught). |
| GTPv2-C | 3GPP TS 29.274 | `dpi_gtp_parser.c` | Message type, TEID (if present), sequence number. Information Elements (APN, IMSI, QoS, etc.) not yet walked. |
| DNS | RFC 1035 | `dpi_dns_parser.c` | Query name (bounds-checked, cycle-safe compression pointer decoding — verified against a cyclic-pointer adversarial test case). **Answer records now walked** for A/AAAA/CNAME types, reusing the same name-decompression routine (which also legitimately handles RRs pointing back to the question name via compression, unlike the question section itself). Authority/additional sections still not walked. |

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

Everything else. Most of what was in this list in earlier versions of
this README (IPv6, HTTP/1.1, DNS answer records, SSH, HTTP/2 at the
frame level, GTP inner-packet recursion, DHCP, SIP/RTP) is now
implemented — see the fully-parsed table above. What's genuinely still
missing: **SMTP/IMAP/POP3**, **SMB**, **MQTT**, **NTP**, **SNMP**, and
industrial/ICS protocols (Modbus, DNP3) if relevant to your deployment.
All would plug into `dpi_dissector_registry.c` following the same
`detect()`/`dissect()` pattern already used throughout — register the
new dissector, add it to `protocols.ini`, done.

### Real gaps within what's now "supported" — don't over-read the table above

A protocol appearing in the fully-parsed table doesn't mean it has no
limitations. Specifically:

| Gap | Where | Why it wasn't fully closed this pass |
|---|---|---|
| HPACK header decompression | `dpi_http2_parser.c` | Genuinely a separate, stateful subsystem (a per-connection dynamic table updated across the whole connection's lifetime, plus Huffman decoding) — comparable in scope to building TCP flow reassembly was, not a small follow-up |
| TCP-over-IPv6 → classification/reassembly | `dpi_ipv6_parser.c` | Needs `dpi_tcp_flow_reassembly.c`'s flow key restructured to hold 128-bit addresses, touching every caller that constructs one — deliberately scoped out to avoid half-wiring something structurally important |
| GTP-in-GTP nested tunnels | `dpi_gtp_parser.c` | Deliberately capped at one level of recursion — unbounded recursion driven by attacker-controlled tunnel depth is a resource-exhaustion vector, not a missing feature |
| DNS authority/additional sections | `dpi_dns_parser.c` | Answer records (the highest-value section) are now walked; authority/additional would follow the identical pattern, just not done yet |
| GTPv2-C Information Elements | `dpi_gtp_parser.c` | Message type + TEID extracted; APN/IMSI/QoS IEs are TLV-encoded and would follow the same bounds-checking pattern as everything else, not done yet |


| File | Role | Depends on |
|---|---|---|
| `dpi_secure_bootstrap.c` | Single-core reference capture loop: opens raw `AF_PACKET` socket as root, drops privileges, installs a seccomp filter. **Wired end-to-end for both TCP and UDP**: TCP → flow reassembly → classification; UDP → RADIUS/QUIC/GTP/DNS dissector registry + VPN fingerprinting, no reassembly (datagram-oriented). Prints one JSON record per flow/datagram to stdout — fine at this scale. Good starting point for lab testing at low traffic rates. | libseccomp, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC, GTP, DNS |
| `dpi_dpdk_worker.c` | Multi-core, DPDK-based capture worker for 100G line rate. RSS across cores, VFIO-based device binding (IOMMU-protected DMA). Wired end-to-end for both TCP and UDP, with 100G-specific care: classification gated to run once per flow (`is_first_delivery`), mbuf freed before classification runs, and output goes through `dpi_async_output.c`'s lock-free ring buffer **feeding a real, configurable sink** (file/syslog/Unix socket, chosen via a command-line argument after DPDK's own EAL args). Contains detailed lab setup instructions in its header comment (IOMMU, hugepages, core isolation) — read those before the code. | DPDK, VFIO-capable NIC/kernel, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC, GTP, DNS, async output, output sink |
| `dpi_async_output.c` | Lock-free per-lcore SPSC ring buffer + dedicated drain pthread, replacing the DPDK worker's earlier hot-path `printf()`. Producers (lcores) never block — a full ring drops and counts, never stalls. Formatting happens only in the drain thread, which now writes through `dpi_output_sink.c`'s pluggable backend instead of `printf`ing directly, with a periodic (1s default) flush schedule. Deliberately a plain pthread, not another DPDK lcore. | `dpi_output_sink.c` |
| `dpi_rfc_parser.c` | RFC-conformant IPv4 (RFC 791), TCP (RFC 9293), and now UDP (RFC 768) parsing: checksum verification, options parsing, IPv4 fragmentation reassembly. States an explicit open decision on TCP overlap-resolution policy (first-wins vs last-wins) rather than silently picking one — implemented in `dpi_tcp_flow_reassembly.c`, see below. | none (self-contained) |
| `dpi_tcp_flow_reassembly.c` | Per-flow TCP stream reassembly sitting on top of the per-segment parsing above. Implements the overlap-resolution policy (configurable FIRST_WINS/LAST_WINS) and, more importantly, detects the actual evasion-relevant case: overlapping segments whose bytes *disagree* at the same position (vs. benign identical retransmission). Timeout eviction + hard flow-count ceiling included. **Flow table is now partitioned per-lcore** (`partition_id` parameter) — an earlier version shared one global table across all lcores with no locking, a real data race caught while wiring this into the multi-core worker. Wired into both capture paths. Includes a test-only reset helper for the fuzz harness. | none (self-contained) |
| `fuzz_*.c` (13 harnesses: rfc_parser, tcp_reassembly, radius, gtp, dns, quic_header, quic_frames, ipv6, http1, http2, ssh, dhcp, sip_rtp) | libFuzzer harnesses for every dissector added so far. QUIC gets two harnesses split at its crypto boundary (see `FUZZING.md` for why). Reviewed but **not compiled or run** — no clang/libFuzzer toolchain available in this sandbox. | See `fuzz_build.sh` |
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
| `dpi_gtp_parser.c` | GTP-U v1 (3GPP TS 29.281) + GTPv2-C (3GPP TS 29.274) dissectors — mobile network user-plane tunneling and control-plane signaling. Extracts TEID, message type, sequence number. Does NOT recursively dissect the inner IP packet inside G-PDU tunnels — flagged as a real scope limit, not silently incomplete. | `dpi_dissector_registry.c` |
| `dpi_dns_parser.c` | DNS (RFC 1035) dissector: header + question section, with bounds-checked, cycle-safe name decompression — verified against an adversarial cyclic-pointer test case, since this is a classic real-world DNS parser bug source. Answer/authority/additional records not yet walked. | `dpi_dissector_registry.c` |
| `dpi_output_sink.c` | Pluggable output backends for `dpi_async_output.c`'s drain thread: file (with SIGHUP/logrotate-compatible reopen), syslog (for alerting/SIEM integration, not recommended as sole high-volume sink), and Unix domain socket (the recommended path for feeding a real message queue — point a dedicated shipper like Fluentd/Vector at the socket rather than embedding a Kafka client in the DPI engine itself). | none (self-contained) |
| `dpi_quic_parser.c` | QUIC (RFC 9000/9001) Initial packet dissector: HKDF key derivation (RFC 9001 §5.2, salt verified against the RFC), header protection removal, AES-128-GCM decryption, and SNI extraction from the decrypted CRYPTO frame (wired end-to-end — an earlier README revision of this row was stale, this has been fixed since). Logic cross-checked against RFC 9001 pseudocode; not yet run against byte-exact test vectors. | OpenSSL (libssl/libcrypto) |
| `dpi_protocol_config.c`, `protocols.ini` | The protocol "arsenal" — central enable/disable config for dissectors, read once at startup. See the dedicated section above. | none (self-contained) |
| `dpi_ipv6_parser.c` | IPv6 (RFC 8200) header + extension header chain parsing, plus IPv6-specific TCP/UDP checksum pseudo-header functions (`parse_tcp_v6`/`parse_udp_v6`). Extension chain walking verified against a 20-header adversarial chain (correctly rejected via a hard cap). | `dpi_rfc_parser.c` (shares `checksum16()`, `struct tcp_result`/`struct udp_result`, option parsing) |
| `dpi_http1_parser.c` | HTTP/1.1 request/status line + Host/User-Agent header extraction. | `dpi_dissector_registry.c` |
| `dpi_http2_parser.c` | HTTP/2 connection preface + frame-level metadata (type, stream ID, RST_STREAM ratio for Rapid-Reset-style abuse detection). HPACK explicitly out of scope — see the file's header comment for why that's a genuinely separate subsystem, not a missed follow-up. | `dpi_dissector_registry.c` |
| `dpi_ssh_parser.c` | SSH identification string + KEXINIT algorithm name-list extraction (plaintext, sent before encryption begins — same pattern as TLS's ClientHello). | `dpi_dissector_registry.c` |
| `dpi_dhcp_parser.c` | DHCP message type, requested IP, hostname, vendor class — plaintext TLV options. | `dpi_dissector_registry.c` |
| `dpi_sip_rtp_parser.c` | SIP (text-based signaling) + RTP (fixed binary media header) in one file, since they're the two halves of a VoIP call though structurally very different. | `dpi_dissector_registry.c` |

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
| `dpi_quic_parser.c` | No | No | SNI extraction wired end-to-end; logic cross-checked against RFC 9001 pseudocode but not run against byte-exact test vectors; packet-number reconstruction simplified (correct for a connection's first Initial packet only); no CRYPTO frame reassembly across multiple packets. Static decryption buffer bug (concurrency hazard) found and fixed while wiring into the multi-core worker. |
| `dpi_protocol_config.c` | No | No | Simple, low-risk file — startup-only config load, no ongoing state to get wrong |
| `dpi_ipv6_parser.c` | No | No | Extension chain walking verified by hand against a 20-header adversarial case (correctly rejected); a real fuzzing pass (`fuzz_ipv6_parser.c`) would give much broader coverage than the handful of hand-checked cases here |
| `dpi_http1_parser.c` | No | No | No chunked transfer-encoding or body parsing; only Host/User-Agent headers extracted, not a general header map |
| `dpi_http2_parser.c` | No | No | HPACK explicitly out of scope (see file header) — `:authority`/header content is NOT available from this dissector, only frame-level metadata |
| `dpi_ssh_parser.c` | No | No | Only 8 of RFC 4253's 10 KEXINIT name-lists extracted (languages lists omitted, almost always empty in practice); nothing past KEXINIT is parsed (correctly — it's encrypted from there) |
| `dpi_dhcp_parser.c` | No | No | Only a handful of the most useful options extracted (message type, requested IP, hostname, vendor class), not a general option map |
| `dpi_sip_rtp_parser.c` | No | No | SIP: only Call-ID/From/To headers extracted, not a general header map. RTP: no port hint exists by protocol design (negotiated via SDP), so `dst_port` is unused in `rtp_detect()` |

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

**Done in this pass**: IPv6 (UDP fully wired; TCP parsed but
deliberately not carried into reassembly/classification — see the gap
table above), HTTP/1.1, HTTP/2 (frame-level), SSH, DHCP, SIP, RTP, GTP-U
inner-packet recursion (bounded to one level), DNS answer records
(A/AAAA/CNAME), the protocol "arsenal" config (`protocols.ini` +
`dpi_protocol_config.c`), and 8 new fuzz harnesses with verified seed
corpora. 13 fuzz harnesses now exist in total, covering every dissector
built so far.

**Two real bugs caught and fixed while doing this work** (same pattern
as earlier passes — integration work surfaces concurrency bugs a
single-file read-through can't):
1. An `extern` re-declaration in `dpi_gtp_parser.c` conflicted with
   `extract_sni_from_record()`'s actual `static` linkage in
   `dpi_app_classifier.c` — fixed by relying on same-translation-unit
   visibility instead, the same pattern already used for `parse_ipv4()`
   in that same function.
2. An early draft of the IPv6 UDP path called `fprintf()` directly on
   the packet-processing path in `dpi_dpdk_worker.c` — exactly the
   hot-path blocking I/O problem `dpi_async_output.c` was built to
   eliminate. Caught before shipping and removed; IPv6 addresses are
   simply not yet surfaced in the flow record rather than reintroducing
   that anti-pattern to work around it.

1. **Actually run the fuzzers.** Now 13 harnesses, still zero of them
   executed — no clang/libFuzzer in this sandbox. This remains the
   single most important thing to do before any of this touches real
   traffic. `fuzz_ipv6_parser.c` and `fuzz_ssh_parser.c` are probably
   worth prioritizing among the new ones — extension header chains and
   repeated length-prefixed field parsing are the two riskiest new
   parsing patterns added this pass.
2. **Compile everything against real dev headers.** Still true for
   every file — the DPDK worker alone now `#include`s 13 files into one
   translation unit.
3. **Validate the QUIC module against RFC 9001 Appendix A.2's test
   vector** — unchanged from before, still not done.
4. **Extend `dpi_tcp_flow_reassembly.c`'s flow key to support IPv6**
   (128-bit addresses) so TCP-over-IPv6 can actually reach
   classification — the single largest deliberately-deferred piece
   from this pass, and now the clearest next architectural step.
5. **Build HPACK decoding for `dpi_http2_parser.c`** if HTTP/2 header
   content (`:authority` specifically) matters for your use case — a
   genuinely separate, stateful subsystem, not a quick addition.
6. **Load-test the async output ring buffer** under realistic burst
   conditions — unchanged from before.
7. **Validate `dpi_vpn_detector.c` and `dpi_doh_dot_detector.c`**
   against real captures — unchanged from before.
8. **Walk GTPv2-C's Information Elements and DNS's authority/additional
   sections** — both flagged as real, contained follow-ups in the gap
   table above, following patterns already built.

