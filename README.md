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
                    │  (L3/L4 dissection)      │  (RFC 9293), checksums,
                    │                          │  options, fragmentation
                    └────────────┬─────────────┘
                                 │ validated TCP/UDP payload
                                 ▼
        ┌────────────────────────────────────────────────┐
        │              dpi_app_classifier.c                │
        │  orchestrates: SNI extraction, domain lookup,     │
        │  DGA scoring, VPN scoring — produces one flow      │
        │  record per connection                            │
        └───┬──────────┬──────────────┬─────────────────┬──┘
            │           │              │                 │
            ▼           ▼              ▼                 ▼
  dpi_domain_rules_  dpi_dga_       dpi_vpn_        dpi_dissector_
  loader.c           detector.c    detector.c       registry.c
  (reads             (lexical      (protocol/port/  (pluggable
  domain_rules.ini,  scoring on    entropy scoring) protocol modules,
  hot-reloadable)    the SNI)                        currently:
                                                      dpi_radius_parser.c
                                                      dpi_quic_parser.c)
```

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

### Detected / scored, not fully dissected

| Protocol | File | What it does |
|---|---|---|
| QUIC | `dpi_quic_parser.c` | RFC 9000/9001: identifies Initial packets, derives keys, removes header protection, AEAD-decrypts the payload, locates the CRYPTO frame. **Does not yet extract SNI from it** — needs a small refactor to hand the decrypted ClientHello (which lacks a TLS record-layer wrapper) to the existing SNI parser. See the file's TODO. |
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
| `dpi_secure_bootstrap.c` | Single-core reference capture loop: opens raw `AF_PACKET` socket as root, drops privileges, installs a seccomp filter, does a bounds-checked Ethernet/IPv4 parse. Good starting point for lab testing at low traffic rates. | libseccomp |
| `dpi_dpdk_worker.c` | Multi-core, DPDK-based capture worker for 100G line rate. RSS across cores, VFIO-based device binding (IOMMU-protected DMA). Contains detailed lab setup instructions in its header comment (IOMMU, hugepages, core isolation) — read those before the code. | DPDK, VFIO-capable NIC/kernel |
| `dpi_rfc_parser.c` | RFC-conformant IPv4 (RFC 791) and TCP (RFC 9293) parsing: checksum verification, options parsing, IPv4 fragmentation reassembly. States an explicit open decision on TCP overlap-resolution policy (first-wins vs last-wins) rather than silently picking one. | none (self-contained) |
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
| `dpi_secure_bootstrap.c` | No (missing dev headers in this sandbox) | No | None known beyond standard review — validate on your lab hardware |
| `dpi_dpdk_worker.c` | No | No | Needs the IOMMU/VFIO/hugepage lab setup described in its header before it's even relevant |
| `dpi_rfc_parser.c` | No | No | Fragment reassembly cache has no timeout eviction or memory ceiling yet; TCP overlap-resolution policy is stated but lives in a not-yet-built flow-reassembly layer |
| `dpi_app_classifier.c` | No | No | JA3 fallback is stubbed, not implemented |
| `dpi_domain_rules_loader.c` | No | No | Reload swap is not thread-safe for the multi-core DPDK worker yet (noted in-code) |
| `domain_rules.ini` | N/A | No | Seed list from general knowledge, not live-verified; will have stale/missing entries |
| `dpi_dga_detector.c` | No | No | Weights are literature-informed starting points, not tuned against a labeled dataset |
| `dpi_vpn_detector.c` | No | No | Byte offsets for WireGuard/IKE unverified against real captures; largely blind to obfuscated/VPN-over-TLS traffic by design |
| `dpi_dissector_registry.c` | No | No | Framework only — O(n) dispatch noted as a possible future bottleneck at very high dissector counts |
| `dpi_radius_parser.c` | No | No | Otherwise structurally complete for the core RFC 2865 fields covered |
| `dpi_quic_parser.c` | No | No | **SNI extraction not wired up yet** (see above); no CRYPTO frame reassembly across multiple packets |

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

1. **Compile everything against real dev headers** and fix whatever
   the compiler catches that a read-through couldn't (this has never
   been through a compiler).
2. **Validate the QUIC module against RFC 9001 Appendix A.2's published
   test vector** before anything else touches it — that's the standard
   way to confirm a from-scratch crypto path is correct.
3. **Wire up the QUIC → SNI handoff** (refactor `extract_sni()` to
   separate record-header parsing from ClientHello-body parsing).
4. **Make the domain-rules reload path thread-safe** (atomic pointer +
   deferred free) before using it inside the multi-core DPDK worker.
5. **Build a real flow-reassembly layer** on top of `dpi_rfc_parser.c`
   to actually implement the TCP overlap-resolution policy, rather than
   parsing individual segments in isolation.
6. **Fuzz each dissector independently** (AFL++/libFuzzer), per the
   very first security checklist in this project — especially
   `dpi_rfc_parser.c` and `dpi_quic_parser.c`, since they parse the
   most attacker-influenced structure.
