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
| IPv6 | RFC 8200 | `dpi_ipv6_parser.c` | Fixed header, extension header chain walking (Hop-by-Hop, Routing, Fragment, Destination Options), bounded against adversarial chains — verified against a 20-header cyclic-looking chain. **Both UDP and TCP now get full treatment**: `struct tcp_flow_key` was extended to hold 128-bit addresses with an explicit IP-version tag (previously sized for IPv4 only), so TCP-over-IPv6 now goes through the identical reassembly → classification pipeline as IPv4. |
| TCP | RFC 9293 | `dpi_rfc_parser.c` | Checksum validation, options (MSS, window scale, SACK-permitted, timestamps). Overlap-resolution policy implemented in `dpi_tcp_flow_reassembly.c`. |
| TLS (ClientHello / SNI) | RFC 8446, RFC 6066 | `dpi_app_classifier.c` | SNI hostname from the ClientHello `server_name` extension. Does not parse the rest of the handshake (cipher suites, other extensions, certificates). |
| HTTP/1.1 | RFC 9110-9112 | `dpi_http1_parser.c` | Request/status line, method, path, status code, Host and User-Agent headers. No chunked transfer-encoding reassembly or body parsing. |
| HTTP/2 | RFC 9113, RFC 7541 (HPACK) | `dpi_http2_parser.c`, `dpi_hpack_decoder.c`, `dpi_hpack_connection_state.c` | Connection preface, frame-level metadata (type, stream ID, length, RST_STREAM ratio), HPACK-decoded header fields (`:authority`, `:method`, `:path`, `:status`). **CONTINUATION frames are now reassembled** when they arrive in the same buffer as their HEADERS frame (the common case) — a CONTINUATION split across a TCP reassembly boundary into a separate call still isn't covered, flagged via `http2_continuation_incomplete_in_buffer`. **The HPACK dynamic table is now connection-persistent**, not fresh-per-frame — kept per TCP flow (keyed the same way `dpi_tcp_flow_reassembly.c` keys TCP state) via `dpi_hpack_connection_state.c`, so cross-frame dynamic-table references resolve correctly for the life of a connection. The Huffman table was verified against three real RFC 7541 Appendix C test vectors before being used. |
| SSH | RFC 4253 | `dpi_ssh_parser.c` | Identification string (protocol/software version), KEXINIT algorithm name-lists (kex, host key, encryption, MAC — 8 of the 10 defined lists). Nothing past key exchange (genuinely encrypted from there). |
| DHCP | RFC 2131/2132 | `dpi_dhcp_parser.c` | Message type, requested IP, hostname, vendor class identifier. |
| SIP | RFC 3261 | `dpi_sip_rtp_parser.c` | Request/status line, method, status code, Call-ID/From/To headers. |
| RTP | RFC 3550 | `dpi_sip_rtp_parser.c` | Payload type, sequence number, timestamp, SSRC, marker bit. No port hint (RTP has no registered port — negotiated per-call via SDP). |
| ICMP | RFC 792 | `dpi_icmp_parser.c` | Type, code, checksum (verified — no pseudo-header needed for ICMPv4). Echo Request/Reply identifier+sequence; Redirect gateway address; Destination Unreachable/Time Exceeded flagged as carrying an embedded original packet (not recursively parsed). Runs directly over IP protocol 1, not TCP/UDP — see the file's header comment on how this fits the dissector interface. |
| ICMPv6 | RFC 4443, RFC 4861 (Neighbor Discovery) | `dpi_icmp_parser.c` | Type, code. Echo Request/Reply identifier+sequence; **Neighbor Solicitation/Advertisement target address extraction** (genuinely useful for on-link host discovery / spoofing detection). Checksum verification happens in the capture path, not inside the dissector — it needs the IPv6 pseudo-header (src/dst addresses), which the generic dissector interface doesn't pass through; same pattern as other protocols whose needs don't fit that shared signature. |
| RADIUS | RFC 2865, RFC 2866 | `dpi_radius_parser.c` | Packet code, identifier, User-Name, NAS-IP-Address, Calling-Station-ID, Acct-Status-Type. `User-Password` is detected as present but its value is deliberately never extracted (credential handling). |
| DNS-over-TLS (DoT) | RFC 7858 | `dpi_doh_dot_detector.c` | Structural detection: port 853 + TLS ClientHello shape. Genuine structural signal, same discipline as the VPN detector. |
| GTP-U v1 | 3GPP TS 29.281 | `dpi_gtp_parser.c` | Message type, TEID, sequence number. **G-PDU inner IP packets are now recursively dissected** (IPv4 only, bounded to exactly one level of nesting — a nested GTP-in-GTP tunnel is detected and flagged, deliberately NOT recursed into further, since unbounded recursion driven by attacker-controlled tunnel depth is exactly the resource-exhaustion vector this project's first security checklist warned about). Inner TCP flows get single-packet SNI extraction (not full flow reassembly — a ClientHello split across multiple G-PDU packets won't be caught). |
| GTPv2-C | 3GPP TS 29.274 | `dpi_gtp_parser.c` | Message type, TEID (if present), sequence number, **and now Information Elements**: IMSI and MSISDN (BCD-decoded per TS 29.274 §8.3/§8.11, verified round-trip against constructed test vectors), APN (label-decoded per TS 23.003 §9.1), and Cause. IMSI/MSISDN are subscriber PII — flagged with a privacy note in the code, same discipline as RADIUS's `User-Password` handling. Other IE types (F-TEID, Bearer QoS, etc.) not yet walked. |
| DNS | RFC 1035 | `dpi_dns_parser.c` | Query name (bounds-checked, cycle-safe compression pointer decoding — verified against a cyclic-pointer adversarial test case). **Answer, authority, and additional records all now walked** (A/AAAA/CNAME/NS types), sharing one bounds-checked section-walking function across all three. |

### Detected / scored, not fully dissected

| Protocol | File | What it does |
|---|---|---|
| QUIC | `dpi_quic_parser.c` | RFC 9000/9001: identifies Initial packets, derives keys, removes header protection, AEAD-decrypts the payload, locates the CRYPTO frame, and now extracts SNI from the enclosed ClientHello (wired to `extract_sni_from_clienthello_body()`, which was split out of the TLS-over-TCP SNI parser specifically because QUIC's CRYPTO frame has no TLS record-layer wrapper — RFC 9001 S4.1.3). Logic cross-checked against RFC 9001's own pseudocode line-by-line; **not yet validated against RFC 9001 Appendix A.2's byte-exact test vectors** — those are two different levels of confidence, see the file header. |
| DNS-over-HTTPS (DoH) | `dpi_doh_dot_detector.c` | No structural fingerprint exists — DoH is indistinguishable from ordinary HTTPS at the wire level. Detection is entirely SNI-based, matching against `domain_rules.ini`'s `[dns_over_https]` category. This is stated plainly rather than implying a cleverer detection method exists. |
| WireGuard | `dpi_vpn_detector.c` | Fingerprints handshake message types/sizes to produce a VPN-likelihood score. Does not parse WireGuard's actual handshake cryptographic fields or transport data. |
| OpenVPN | `dpi_vpn_detector.c` | Recognizes the opcode byte pattern for a VPN-likelihood score. No further field extraction. |
| IKE / IPsec (IKEv1/IKEv2) | `dpi_vpn_detector.c` | Validates the ISAKMP header shape and version for a VPN-likelihood score. No payload/SA parsing. |
| Encrypted Client Hello (ECH) | `dpi_app_classifier.c` | Recognized only as "SNI absent, TLS 1.3 handshake" — not decoded (ECH decoding would require the ECH config's private key, which a network observer doesn't have by design). |

### Not supported yet, and what's worth adding next

Everything not in the fully-parsed table above. Most of what was
recommended in earlier versions of this README (IPv6, HTTP/1.1, DNS
answer records, SSH, HTTP/2 at the frame level + HPACK + CONTINUATION
reassembly + connection persistence, GTP inner-packet recursion, DHCP,
SIP/RTP, GTPv2-C IEs, ICMP/ICMPv6) is now implemented. Here's a fresh
prioritized list for what's genuinely still missing:

| Protocol | Value | Effort relative to what's built |
|---|---|---|
| **SMTP** | Medium-high — mail server visibility (HELO/EHLO, MAIL FROM, RCPT TO), useful for detecting mail relay abuse/spam | Low-medium — text-based command/response protocol, similar shape to SIP's request/response line parsing already built |
| **SMB/CIFS** | Medium — significant for internal/enterprise network visibility (file share access, lateral movement detection) | Higher — SMB2/3 has a more complex, binary, multi-command structure than the text protocols built so far |
| **MQTT** | Medium, IoT-specific — connect/publish/subscribe visibility for IoT deployments | Low — compact binary protocol, simpler than most already built (RADIUS-level complexity) |
| **NTP** | Low-medium, but cheap | Low — fixed 48-byte header, straightforward |
| **SNMP** | Medium, network-management-specific | Medium — BER/ASN.1 encoding is a new parsing paradigm not used elsewhere in this project (everything so far is fixed-field or simple TLV) |
| **Modbus/DNP3** (ICS/SCADA) | Situational — high value specifically for industrial/OT network monitoring, irrelevant otherwise | Low-medium — both are simpler, more fixed-structure protocols than most already built |
| **ARP** | Low value alone, but cheap and sometimes useful for on-link visibility (ARP spoofing detection) | Very low — trivial fixed-format protocol |
| **STUN/TURN** | Situational — relevant if WebRTC/VoIP traffic matters for your deployment (NAT traversal visibility) | Medium — STUN's TLV attribute structure is similar to what's already built; the ICE/TURN relay logic adds real complexity beyond basic message parsing |

All of these would plug into `dpi_dissector_registry.c` following the
same `detect()`/`dissect()` pattern already used throughout — register
the new dissector, add it to `protocols.ini`, done. SMTP or ARP are
probably the cheapest next additions if you want another quick win
before tackling something larger like SMB or SNMP.

### Real gaps within what's now "supported" — don't over-read the table above

A protocol appearing in the fully-parsed table doesn't mean it has no
limitations. Most of what was in this table in the previous README
revision (TCP-over-IPv6 classification, DNS authority/additional
sections, GTPv2-C Information Elements, GTP-U inner-packet recursion,
HPACK per-connection persistence, HTTP/2 CONTINUATION reassembly) is
now closed — see the fully-parsed table above. What remains:

| Gap | Where | Why it wasn't fully closed this pass |
|---|---|---|
| GTP-in-GTP nested tunnels | `dpi_gtp_parser.c` | Deliberately capped at one level of recursion — unbounded recursion driven by attacker-controlled tunnel depth is a resource-exhaustion vector, not a missing feature |
| GTPv2-C: only 4 IE types decoded | `dpi_gtp_parser.c` | IMSI, MSISDN, APN, and Cause are walked; F-TEID, Bearer QoS, and other IE types are skipped by length rather than parsed — same bounds-checking pattern, just not extended to every IE type yet |
| GTP-U inner-packet IPv6 | `dpi_gtp_parser.c` | Inner-packet recursion only handles an IPv4 inner packet — an IPv6 inner packet is detected but not dissected (would need `dpi_ipv6_parser.c` wired into the same recursive call) |
| ICMP/ICMPv6 original-packet embedding not parsed | `dpi_icmp_parser.c` | Destination Unreachable/Time Exceeded messages carry the offending original packet — flagged as present, not recursively dissected (would follow the same pattern as GTP-U inner-packet recursion) |
| HTTP/2 CONTINUATION across a TCP reassembly boundary | `dpi_http2_parser.c` | Reassembly only works when CONTINUATION frames arrive in the SAME buffer as their HEADERS frame (the common case, since implementations typically send them back-to-back). A CONTINUATION split across a separate `dissect()` call isn't covered — flagged via `http2_continuation_incomplete_in_buffer` |
| HPACK's default table size is hardcoded to 4096 | `dpi_hpack_connection_state.c`, `dpi_http2_parser.c` | Real HTTP/2 negotiates `SETTINGS_HEADER_TABLE_SIZE` per-connection via SETTINGS frames; this reference implementation doesn't track that negotiation, so a connection that negotiates a non-default size could be decoded against the wrong table size limit |



| File | Role | Depends on |
|---|---|---|
| `dpi_secure_bootstrap.c` | Single-core reference capture loop: opens raw `AF_PACKET` socket as root, drops privileges, installs a seccomp filter. **Wired end-to-end for both TCP and UDP**: TCP → flow reassembly → classification; UDP → RADIUS/QUIC/GTP/DNS dissector registry + VPN fingerprinting, no reassembly (datagram-oriented). Prints one JSON record per flow/datagram to stdout — fine at this scale. Good starting point for lab testing at low traffic rates. | libseccomp, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC, GTP, DNS |
| `dpi_dpdk_worker.c` | Multi-core, DPDK-based capture worker for 100G line rate. RSS across cores, VFIO-based device binding (IOMMU-protected DMA). Wired end-to-end for both TCP and UDP, with 100G-specific care: classification gated to run once per flow (`is_first_delivery`), mbuf freed before classification runs, and output goes through `dpi_async_output.c`'s lock-free ring buffer **feeding a real, configurable sink** (file/syslog/Unix socket, chosen via a command-line argument after DPDK's own EAL args). Contains detailed lab setup instructions in its header comment (IOMMU, hugepages, core isolation) — read those before the code. | DPDK, VFIO-capable NIC/kernel, and (via `#include`) the RFC parser, flow reassembly, classifier, dissector registry, RADIUS, QUIC, GTP, DNS, async output, output sink |
| `dpi_async_output.c` | Lock-free per-lcore SPSC ring buffer + dedicated drain pthread, replacing the DPDK worker's earlier hot-path `printf()`. Producers (lcores) never block — a full ring drops and counts, never stalls. Formatting happens only in the drain thread, which now writes through `dpi_output_sink.c`'s pluggable backend instead of `printf`ing directly, with a periodic (1s default) flush schedule. Deliberately a plain pthread, not another DPDK lcore. | `dpi_output_sink.c` |
| `dpi_rfc_parser.c` | RFC-conformant IPv4 (RFC 791), TCP (RFC 9293), and now UDP (RFC 768) parsing: checksum verification, options parsing, IPv4 fragmentation reassembly. States an explicit open decision on TCP overlap-resolution policy (first-wins vs last-wins) rather than silently picking one — implemented in `dpi_tcp_flow_reassembly.c`, see below. | none (self-contained) |
| `dpi_tcp_flow_reassembly.c` | Per-flow TCP stream reassembly sitting on top of the per-segment parsing above. Implements the overlap-resolution policy (configurable FIRST_WINS/LAST_WINS) and, more importantly, detects the actual evasion-relevant case: overlapping segments whose bytes *disagree* at the same position (vs. benign identical retransmission). Timeout eviction + hard flow-count ceiling included. **Flow table is now partitioned per-lcore** (`partition_id` parameter) — an earlier version shared one global table across all lcores with no locking, a real data race caught while wiring this into the multi-core worker. Wired into both capture paths. Includes a test-only reset helper for the fuzz harness. | none (self-contained) |
| `fuzz_*.c` (15 harnesses: rfc_parser, tcp_reassembly, radius, gtp, dns, quic_header, quic_frames, ipv6, http1, http2, ssh, dhcp, sip_rtp, hpack_decoder, icmp) | libFuzzer harnesses for every dissector added so far. QUIC gets two harnesses split at its crypto boundary (see `FUZZING.md` for why). `fuzz_hpack_decoder.c` targets the HPACK decoder directly — the highest-risk new component in this project, worth prioritizing. Reviewed but **not compiled or run** — no clang/libFuzzer toolchain available in this sandbox. | See `fuzz_build.sh` |
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
| `dpi_icmp_parser.c` | ICMP (RFC 792) + ICMPv6 (RFC 4443/4861) dissectors. Runs directly over IP, not TCP/UDP — the capture path has dedicated branches for IP protocol 1 / IPv6 next_header 58, since there's no port to dispatch on. ICMPv6 checksum verification happens in the capture path (needs IPv6 addresses the generic interface doesn't pass through), not inside the dissector. | `dpi_dissector_registry.c` |
| `dpi_hpack_connection_state.c` | Per-flow persistent HPACK dynamic table, keyed by the same `tcp_flow_key` `dpi_tcp_flow_reassembly.c` uses — closes the "HPACK dynamic table is per-frame, not per-connection" gap. Partitioned per-lcore (reuses `TCP_REASSEMBLY_NUM_PARTITIONS`), with its own (longer) timeout since HTTP/2 connections are typically longer-lived than raw TCP flows. | `dpi_tcp_flow_reassembly.c`, `dpi_hpack_decoder.c` |
| `dpi_hpack_decoder.c` | HPACK (RFC 7541) decoder for HTTP/2: static table (61 entries), integer/string decoding, Huffman decoding, and a per-call dynamic table. The 257-entry Huffman table was verified before use — transcribed to Python, checked structurally (complete prefix code, no duplicates), then used to correctly decode three independent real byte sequences from RFC 7541 Appendix C, and the C table was generated programmatically from that verified source rather than hand-retyped. | none (self-contained) |

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
| `dpi_icmp_parser.c` | No | No | Original-packet embedding in Destination Unreachable/Time Exceeded not recursively parsed (flagged, not dissected) |
| `dpi_hpack_connection_state.c` | No | No | Hardcoded 4096-byte default dynamic table size (see gap table above) — no real SETTINGS_HEADER_TABLE_SIZE negotiation tracking |
| `dpi_http2_parser.c` (updated) | No | No | CONTINUATION reassembly only works within one buffer (documented gap); dynamic table size still hardcoded at connection-creation time |
| `dpi_hpack_decoder.c` | No | No | Huffman table verified against 3 real RFC test vectors (high confidence); dynamic table is per-call only, not connection-persistent (see gap table above) — this is the most novel, least-precedented code in this project, worth prioritizing for fuzzing |
| `dpi_tcp_flow_reassembly.c` (updated) | No | No | Flow key now supports IPv6 (128-bit addresses, explicit version tag) via `tcp_flow_key_make_v4()`/`_v6()` constructors — all call sites updated; verify this compiles cleanly given the struct layout change touched multiple files |

## Sample JSON output, one per fully-parsed protocol

Every sample below is a plausible flow/dissection record for that
specific protocol — not from a live run (nothing here has actually
been executed), but each field matches what that dissector's code
genuinely extracts, so this is a reliable preview of real output
shape, not aspirational.

**IPv4 + TCP + TLS/SNI** (the original baseline path):
```json
{"src_ip":"10.0.4.17","dst_ip":"157.240.22.35","src_port":51422,"dst_port":443,
 "sni":"instagram.com","category":"social_media","app_name":"Instagram",
 "confidence":"high","dga_score":0.06,"vpn_score":0.0,"vpn_protocol":"none",
 "dot_score":0.0,"doh_score":0.0,
 "reassembly":{"out_of_order":0,"retransmits":1,"overlap_conflicts":0,"evasion_flag":false}}
```

**IPv6 + TCP** (now fully wired, not deferred):
```json
{"src_ip":"2001:db8::1","dst_ip":"2606:2800:220:1:248:1893:25c8:1946",
 "src_port":54210,"dst_port":443,"sni":"example.com","category":"unclassified",
 "confidence":"low","dga_score":0.03,"vpn_score":0.0,"vpn_protocol":"none",
 "dot_score":0.0,"doh_score":0.0,
 "reassembly":{"out_of_order":0,"retransmits":0,"overlap_conflicts":0,"evasion_flag":false}}
```

**RADIUS**:
```json
{"protocol":"RADIUS","radius_code":"Access-Request","radius_identifier":"5",
 "user_name":"jsmith","user_password_present":"true",
 "nas_ip_address":"10.0.1.1","calling_station_id":"00-1A-2B-3C-4D-5E"}
```

**GTP-U v1** (with recursively-dissected inner packet):
```json
{"protocol":"GTPv1-U","gtp_message_type":"G-PDU","gtp_teid":"0x12345678",
 "gtp_sequence_number":"42","gtp_inner_packet_present":"true",
 "gtp_inner_src_ip":"10.1.1.1","gtp_inner_dst_ip":"93.184.216.34",
 "gtp_inner_protocol":"TCP","gtp_inner_dst_port":"443",
 "gtp_inner_sni":"example.com"}
```

**GTPv2-C** (with IMSI/APN/Cause IEs):
```json
{"protocol":"GTPv2-C","gtpv2_message_type":"Create Session Request",
 "gtpv2_teid":"0xaabbccdd","gtpv2_sequence_number":"555",
 "gtpv2_ie_0_imsi":"310150123456789",
 "gtpv2_ie_1_apn":"internet.mnc001.mcc310.gprs",
 "gtpv2_ie_2_cause":"16","gtpv2_ie_count":"3"}
```

**DNS** (query + A-record answer):
```json
{"protocol":"DNS","dns_is_response":"true","dns_opcode":"0","dns_rcode":"0",
 "dns_qname":"example.com","dns_qtype":"1","dns_qclass":"1",
 "dns_answer_0_a":"93.184.216.34","dns_answer_records_parsed":"1",
 "dns_authority_records_parsed":"0","dns_additional_records_parsed":"0"}
```

**HTTP/1.1**:
```json
{"protocol":"HTTP/1.1","http_is_response":"false","http_method":"GET",
 "http_path":"/index.html","http_host":"example.com",
 "http_user_agent":"curl/8.0"}
```

**HTTP/2** (with HPACK-decoded pseudo-headers):
```json
{"protocol":"HTTP/2","http2_preface_present":"true","http2_frames_parsed":4,
 "http2_headers_frame_count":1,"http2_rst_stream_count":0,
 "http2_max_stream_id":1,"http2_authority":"www.example.com",
 "http2_method":"GET","http2_path":"/"}
```

**SSH**:
```json
{"protocol":"SSH","ssh_identification_string":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
 "ssh_protocol_version":"2.0","ssh_software_version":"OpenSSH_8.9p1",
 "ssh_kexinit_present":"true","ssh_kex_algorithms":"curve25519-sha256",
 "ssh_encryption_algorithms_client_to_server":"aes128-ctr"}
```

**DHCP**:
```json
{"protocol":"DHCP","dhcp_op":"BOOTREQUEST","dhcp_message_type":"DHCPDISCOVER",
 "dhcp_hostname":"laptop-jsmith"}
```

**SIP**:
```json
{"protocol":"SIP","sip_is_response":"false","sip_method":"INVITE",
 "sip_call_id":"abc123@example.com","sip_from":"<sip:alice@example.com>",
 "sip_to":"<sip:bob@example.com>"}
```

**RTP**:
```json
{"protocol":"RTP","rtp_payload_type":"0","rtp_sequence_number":"1000",
 "rtp_timestamp":"90000","rtp_ssrc":"0xabcdef01","rtp_marker":"false",
 "rtp_csrc_count":"0"}
```

**ICMP** (Echo Request — ping):
```json
{"src_ip":"10.0.4.17","dst_ip":"8.8.8.8","protocol":"ICMP",
 "icmp_type":"Echo Request","icmp_code":"0","icmp_checksum_valid":"true",
 "icmp_echo_identifier":"4660","icmp_echo_sequence":"1"}
```

**ICMPv6** (Neighbor Solicitation):
```json
{"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","protocol":"ICMPv6",
 "icmpv6_type":"Neighbor Solicitation","icmpv6_code":"0",
 "icmpv6_checksum_valid":"true",
 "icmpv6_nd_target_address":"2001:db8::1"}
```

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

**Done in this pass**: ICMP/ICMPv6 (including Neighbor Discovery target
extraction). HTTP/2 CONTINUATION frame reassembly (same-buffer case).
HPACK connection-level persistence via `dpi_hpack_connection_state.c`,
keyed by the same `tcp_flow_key` TCP reassembly uses. Two attempts made
to fetch RFC 9001 Appendix A.2's exact test vector for QUIC validation
— both unsuccessful (see below) — genuinely still open. 2 new fuzz
harnesses (`fuzz_icmp_parser.c`, plus the HPACK decoder's signature
refactor propagated through `fuzz_hpack_decoder.c`) — 15 total now.

**Real bugs found and fixed while doing this work** — this pass found
more of these than most, worth listing individually rather than
glossing over:

1. **A previously-unnoticed, significant gap**: `dpi_http1_parser.c`,
   `dpi_http2_parser.c`, and `dpi_ssh_parser.c` were all registered
   into the dissector registry but **nothing on the TCP capture path
   ever actually called `dispatch_dissection()` against reassembled
   TCP data** — only `classify_flow()`'s TLS/SNI-specific path was
   ever invoked. They were registered dead code until this pass wired
   TCP-based dissector dispatch into both capture files (gated to only
   run when no TLS ClientHello was found, so it doesn't cost anything
   on the already-working TLS path).
2. **A genuinely missing field**: the primary IPv4-TCP flow record
   construction in `dpi_dpdk_worker.c` never copied the classified SNI
   into `rec.sni` — every OTHER path (IPv6 TCP, IPv6 UDP, QUIC-over-
   UDP) did this correctly, but the original, most-used path silently
   dropped it. Found while reviewing that same code block for the
   HTTP/2 wiring above, fixed immediately.
3. **A duplicate `#include` in `dpi_http2_parser.c`** — `#include
   "dpi_hpack_decoder.c"` appeared twice, which would have caused a
   redefinition compile error for every symbol in that file. Left over
   from an earlier edit; caught on a routine re-read before shipping.
4. **A dangling-pointer bug caught before it shipped**: an early draft
   of the IPv6 TCP path's HTTP/2 wiring in `dpi_secure_bootstrap.c`
   kept `const char *` pointers into `dissect_result` structs that were
   declared inside a nested `if` block — those structs go out of scope
   before the `printf()` that used the pointers runs. Fixed by copying
   into fixed-size buffers that outlive the block, instead of holding
   pointers into stack memory that's no longer valid.
5. **The same static-buffer concurrency pattern caught for QUIC
   earlier in this project almost recurred**: an early draft of the
   HTTP/2 CONTINUATION-reassembly buffer was declared `static uint8_t
   combined_block[16384]` — exactly the kind of shared-across-
   concurrent-lcore-calls bug already found and fixed once before.
   Caught immediately this time (the pattern was already known) and
   made a stack variable instead.

None of these would have been caught by reviewing any single file in
isolation — all five surfaced specifically while wiring components
together and re-reading code that had already "worked" in a narrower
sense.

1. **Actually run the fuzzers.** Now 15 harnesses, still zero executed
   — no clang/libFuzzer in this sandbox, unchanged from every previous
   version of this list. `fuzz_hpack_decoder.c` remains the single
   highest-priority target: the most novel, least-precedented parsing
   logic in the project, verified by hand against real RFC test
   vectors but never actually fuzzed.
2. **Compile everything against real dev headers.** Still true for
   every file. This is worth stating plainly at this point: an
   enormous amount of care has gone into logic verification (Python
   models, RFC cross-checks, adversarial test cases) specifically
   *because* nothing here can be compiled in this sandbox — but that
   verification is a substitute for testing, not equivalent to it.
   Compiling and running this for real remains the top unconditional
   priority regardless of how much logic review precedes it.
3. **Get RFC 9001 Appendix A.2's exact test vector.** Two documented
   attempts this pass — a direct RFC fetch that truncated before the
   appendix's hex content (twice, at two different URL anchors), and a
   search that only surfaced fragments from pre-final IETF drafts
   using mismatched version identifiers (`0xff000020` instead of the
   final `0x00000001`), which wouldn't produce byte-matching results
   even if fully assembled. This remains the *only* item in the
   project still at "logic cross-checked against RFC pseudocode" rather
   than "verified against real test vectors or adversarial cases" —
   everything else that once carried that caveat (DNS decompression,
   IPv6 extension chains, HPACK Huffman/header-block decoding) has
   since been checked against real published examples. Get the actual
   RFC text (a PDF or a non-truncating fetch) and this becomes a
   short, mechanical validation.
4. **Track real SETTINGS_HEADER_TABLE_SIZE negotiation** for HPACK,
   instead of the hardcoded 4096-byte default — see the gap table
   above.
5. **Recursively dissect ICMP/ICMPv6's embedded original packet**
   (Destination Unreachable / Time Exceeded messages carry it) — same
   pattern as GTP-U inner-packet recursion, not yet extended here.
6. **Load-test the async output ring buffer** under realistic burst
   conditions — unchanged from before.
7. **Validate `dpi_vpn_detector.c` and `dpi_doh_dot_detector.c`**
   against real captures — unchanged from before.
8. **Add SMTP or ARP** as the next protocol additions — see the
   recommendation table above for the fuller prioritized list.

