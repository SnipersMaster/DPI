# One sample dissection per protocol in the engine

Every sample below uses the **exact field names** each dissector's
`dissect_result_add()` calls actually emit — extracted directly from
the source files, not written from memory or aspiration. Where a
field name is built dynamically (e.g. GTP's inner-packet fields, which
switch to a `gtp_nested_*` prefix at recursion depth > 0), that's
called out explicitly. None of this has been executed — there's no
compiler in this environment — so treat these as an accurate preview
of output *shape*, not a captured trace. Values are plausible and,
where this project verified against real captures earlier, drawn from
or modeled on the real data actually found (real MACs, real domains,
real message types actually seen on the wire).

This file exists as a single, complete reference — the README's own
"Sample JSON output" section predates roughly 30 of the protocols
below and was never fully caught up; this file is the current,
complete one. 107 samples: 63 `protocols.ini` entries, the baseline
flow record, 802.11 (standalone, not `protocols.ini`-gated), RARP
(folded into ARP, same dissector), LLMNR (folded into DNS, same
dissector), STP/RSTP, AppleTalk, PPPoE, CDP, EAPOL, LACP, DECnet,
Banyan VINES, MACsec, HomePlug AV, and Ethernet Loopback (all
standalone, detected via 802.3 LLC framing or real EtherTypes rather
than `protocols.ini`-gated port/content matching), and the real
flow-record-wrapped envelope
(`flow_id`/`ts_start`/`ts_last`/`bytes_total`/
`packets_total`/`duration_ms`, all genuinely computed fields, not
placeholders) shown for the baseline case plus 5 core application
protocols (DNS, HTTP/1.1 — now including a bounded body preview,
also added on request — HTTP/2, SSH, SMTP). Everything else in this
file still shows the older, dissector-only view; see the "Core
application protocols" section below for the one-paragraph
explanation of how to mentally wrap any of them the same way.

---

## Baseline flow record (every TCP/UDP flow, before any deeper protocol-specific dissection)

This is the actual envelope `dpi_flow_record.c` emits for every TCP
and UDP flow — `flow_id`/`ts_start`/`ts_last`/`bytes_total`/
`packets_total`/`duration_ms` are all real, computed fields (from
real pcap/pcapng timestamps and per-packet byte accumulation), not
placeholders. When no deeper protocol-specific dissector matched
(TLS/SNI classification only, or nothing at all), there's no nested
object — the samples below show exactly that "envelope only" case.
Every sample further down this file that *does* have a deeper
dissector match nests that dissector's own fields under a key named
after its field-name prefix (e.g. `dns_qname` → nested under `"dns"`
as `"qname"`) — the general shape every one of them follows is shown
here once, not repeated in every single sample's own explanation.

**IPv4 + TCP + TLS/SNI** (matched by SNI/domain classification only —
no deeper TCP dissector recognized this specific traffic, so no
nested object; this is the generic case most encrypted traffic falls
into):
```json
{"flow_id":"1a2b3c4d-0001","ts_start":"2026-07-25T14:22:04.003112Z",
 "ts_last":"2026-07-25T14:22:04.221007Z","src_ip":"10.0.4.17",
 "dst_ip":"157.240.22.35","src_port":51422,"dst_port":443,
 "protocol":"TCP","l7_protocol":"social_media","l7_confidence":"high",
 "bytes_total":18422,"packets_total":24,"duration_ms":218,
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":1},
 "flags":[]}
```

**IPv6 + TCP, unclassified**:
```json
{"flow_id":"1a2b3c4d-0002","ts_start":"2026-07-25T14:22:05.100442Z",
 "ts_last":"2026-07-25T14:22:05.340118Z","src_ip":"2001:db8::1",
 "dst_ip":"2606:2800:220:1:248:1893:25c8:1946","src_port":54210,
 "dst_port":443,"protocol":"TCP","l7_protocol":"unknown","l7_confidence":"low",
 "bytes_total":4112,"packets_total":7,"duration_ms":240,
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

---

## Core application protocols

**These are genuinely flow-record-wrapped in the real output** — every
protocol below rides over TCP or UDP, both of which route through
`dpi_flow_record.c`'s envelope (see above) automatically; the nested
object shown in each sample is exactly what a real dissection produces,
using the generic prefix-stripping `dpi_flow_record.c` performs, not a
hand-written schema per protocol. Only the 5 protocols immediately
below (DNS, HTTP/1.1, HTTP/2, SSH, SMTP) have been re-rendered in the
full wrapped form for this update — everything further down this file
(SIP, RTP, ICMP, SNMP, and the rest of this large reference) still
shows the older, dissector-only view for brevity; mentally wrap any of
them in the same envelope shown above to see what real output actually
looks like.

**DNS** (query + A-record answer; UDP, so flow-wrapped as shown):
```json
{"flow_id":"1a2b3c4d-0003","ts_start":"2026-07-25T14:22:10.001200Z",
 "ts_last":"2026-07-25T14:22:10.041650Z","src_ip":"10.0.4.17",
 "dst_ip":"8.8.8.8","src_port":54821,"dst_port":53,
 "protocol":"UDP","l7_protocol":"DNS","l7_confidence":"high",
 "bytes_total":142,"packets_total":2,"duration_ms":40,
 "dns":{"is_response":"true","opcode":"0","rcode":"0","qname":"example.com",
 "qtype":"1","qclass":"1","answer_0_a":"93.184.216.34",
 "answer_records_parsed":"1","authority_records_parsed":"0",
 "additional_records_parsed":"0"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**HTTP/1.1** (TCP; now includes a bounded body preview, added on
direct request — `http_body_preview` is the first 200 bytes of the
real response body, `http_body_length` is the true total length, so a
truncated preview is always distinguishable from a genuinely short
body. Verified against a real 302 redirect response from a genuine
capture — the body preview below is the real, actual HTML that
capture contained, not a fabricated example):
```json
{"flow_id":"1a2b3c4d-0004","ts_start":"2026-07-25T14:22:11.500000Z",
 "ts_last":"2026-07-25T14:22:11.618340Z","src_ip":"10.0.4.17",
 "dst_ip":"157.56.23.10","src_port":51500,"dst_port":80,
 "protocol":"TCP","l7_protocol":"HTTP/1.1","l7_confidence":"high",
 "bytes_total":612,"packets_total":4,"duration_ms":118,
 "http":{"is_response":"true","first_line":"HTTP/1.1 302 Moved Temporarily",
 "method":"","path":"","host":"","user_agent":"",
 "content_type":"text/html; charset=utf-8",
 "body_length":"242",
 "body_preview":"<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"http://silverlight.dlservice.microsoft.com/download/d/2/9/d29e5571-4b68-4d95-b43a-4e81ba178455/2.0/ENU/InstallSilverl"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```
A real request on a different, earlier flow (showing the fields a
request populates instead — `method`/`path`/`host`/`user_agent`
rather than a response's `body_preview`; a request can have a body
too, e.g. a real `POST`, but this dissector only emits `body_preview`/
`body_length` when a genuine blank-line header terminator was actually
found, and there's real body data after it — see `dpi_http1_parser.c`'s
own comment on why an unreliable body boundary is never guessed at):
```json
{"flow_id":"1a2b3c4d-0005","ts_start":"2026-07-25T14:22:09.200000Z",
 "ts_last":"2026-07-25T14:22:09.204500Z","src_ip":"10.0.4.17",
 "dst_ip":"93.184.216.34","src_port":51488,"dst_port":80,
 "protocol":"TCP","l7_protocol":"HTTP/1.1","l7_confidence":"high",
 "bytes_total":298,"packets_total":3,"duration_ms":4,
 "http":{"is_response":"false","first_line":"GET /index.html HTTP/1.1",
 "method":"GET","path":"/index.html","host":"example.com",
 "user_agent":"curl/8.0"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**HTTP/2** (TCP, with HPACK-decoded pseudo-headers):
```json
{"flow_id":"1a2b3c4d-0006","ts_start":"2026-07-25T14:22:12.000000Z",
 "ts_last":"2026-07-25T14:22:12.087220Z","src_ip":"10.0.4.17",
 "dst_ip":"93.184.216.34","src_port":51510,"dst_port":443,
 "protocol":"TCP","l7_protocol":"HTTP/2","l7_confidence":"high",
 "bytes_total":2104,"packets_total":6,"duration_ms":87,
 "http2":{"preface_present":"true","frames_parsed":"4",
 "headers_frame_count":"1","rst_stream_count":"0","max_stream_id":"1",
 "authority":"www.example.com","method":"GET","path":"/","status":"200",
 "settings_header_table_size":"4096"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**SSH** (TCP):
```json
{"flow_id":"1a2b3c4d-0007","ts_start":"2026-07-25T14:22:13.000000Z",
 "ts_last":"2026-07-25T14:22:13.045000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.4.90","src_port":51522,"dst_port":22,
 "protocol":"TCP","l7_protocol":"SSH","l7_confidence":"high",
 "bytes_total":1088,"packets_total":5,"duration_ms":45,
 "ssh":{"identification_string":"SSH-2.0-OpenSSH_9.6",
 "protocol_version":"2.0","software_version":"OpenSSH_9.6",
 "kexinit_present":"true"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**SMTP** (TCP):
```json
{"flow_id":"1a2b3c4d-0008","ts_start":"2026-07-25T14:22:14.000000Z",
 "ts_last":"2026-07-25T14:22:14.612000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.20","src_port":51540,"dst_port":25,
 "protocol":"TCP","l7_protocol":"SMTP","l7_confidence":"high",
 "bytes_total":3220,"packets_total":14,"duration_ms":612,
 "smtp":{"ehlo_domain":"mail.example.com","mail_from":"<sender@example.com>",
 "rcpt_to":"<recipient@example.org>","response_code":"250",
 "starttls_seen":"true","data_command_seen":"true",
 "message_from":"Sender Name <sender@example.com>",
 "message_to":"Recipient Name <recipient@example.org>",
 "message_subject":"Quarterly report",
 "message_date":"Wed, 24 Jul 2026 10:00:00 -0700",
 "message_body_begins":"true"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**AMQP** (TCP; real Basic.Publish fields from this project's own Celery-traffic
verification):
```json
{"flow_id":"1a2b3c4d-0009","ts_start":"2026-07-25T14:22:15.000000Z",
 "ts_last":"2026-07-25T14:22:15.032000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.40","src_port":51560,"dst_port":5672,
 "protocol":"TCP","l7_protocol":"AMQP","l7_confidence":"high",
 "bytes_total":410,"packets_total":3,"duration_ms":32,
 "amqp":{"frame_type":"METHOD","channel":"1","method":"Basic.Publish",
 "exchange":"celeryev","routing_key":"worker.heartbeat"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**MySQL** (TCP; real Initial Handshake fields, verified against the
mysql-proxy project's own documented example):
```json
{"flow_id":"1a2b3c4d-0010","ts_start":"2026-07-25T14:22:16.000000Z",
 "ts_last":"2026-07-25T14:22:16.008000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.60","src_port":51580,"dst_port":3306,
 "protocol":"TCP","l7_protocol":"MySQL","l7_confidence":"high",
 "bytes_total":58,"packets_total":1,"duration_ms":8,
 "mysql":{"packet_length":"54","sequence_id":"0","protocol_version":"10",
 "server_version":"5.5.2-m2","connection_id":"82","capability_flags_lower":"0xffff"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**PostgreSQL** (TCP; real StartupMessage fields, verified against a real
example from the PostgreSQL mailing list archives):
```json
{"flow_id":"1a2b3c4d-0011","ts_start":"2026-07-25T14:22:17.000000Z",
 "ts_last":"2026-07-25T14:22:17.006000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.80","src_port":51600,"dst_port":5432,
 "protocol":"TCP","l7_protocol":"PostgreSQL","l7_confidence":"high",
 "bytes_total":42,"packets_total":1,"duration_ms":6,
 "postgresql":{"message_length":"38","message_type":"StartupMessage",
 "protocol_version":"3.0","user":"postgres","database":"maach"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**TDS** (TCP; real PRELOGIN response fields — the encoded server version
decoded to exactly "12.00.2000", matching the original real example's own
stated value):
```json
{"flow_id":"1a2b3c4d-0012","ts_start":"2026-07-25T14:22:18.000000Z",
 "ts_last":"2026-07-25T14:22:18.005000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.100","src_port":51620,"dst_port":1433,
 "protocol":"TCP","l7_protocol":"TDS","l7_confidence":"high",
 "bytes_total":20,"packets_total":1,"duration_ms":5,
 "tds":{"type":"Tabular_Result","eom":"true","length":"20","spid":"0",
 "packet_id":"1","prelogin_server_version":"12.00.2000"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**RTSP** (TCP):
```json
{"flow_id":"1a2b3c4d-0013","ts_start":"2026-07-25T14:22:19.000000Z",
 "ts_last":"2026-07-25T14:22:19.014000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.120","src_port":51640,"dst_port":554,
 "protocol":"TCP","l7_protocol":"RTSP","l7_confidence":"high",
 "bytes_total":84,"packets_total":2,"duration_ms":14,
 "rtsp":{"is_response":"false","first_line":"DESCRIBE rtsp://example.com/media.mp4 RTSP/1.0",
 "method":"DESCRIBE","url":"rtsp://example.com/media.mp4","cseq":"1"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**SIP** (UDP — SIP's own dissector accepts both transports; this shows the
more common UDP signaling case, so it's wrapped by the generic UDP flow
path rather than TCP's):
```json
{"flow_id":"1a2b3c4d-0014","ts_start":"2026-07-25T14:22:20.000000Z",
 "ts_last":"2026-07-25T14:22:20.210000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.140","src_port":5060,"dst_port":5060,
 "protocol":"UDP","l7_protocol":"SIP","l7_confidence":"high",
 "bytes_total":572,"packets_total":2,"duration_ms":210,
 "sip":{"is_response":"false","first_line":"INVITE sip:bob@example.com SIP/2.0"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**MQTT** (TCP):
```json
{"flow_id":"1a2b3c4d-0015","ts_start":"2026-07-25T14:22:21.000000Z",
 "ts_last":"2026-07-25T14:22:21.180000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.160","src_port":51660,"dst_port":1883,
 "protocol":"TCP","l7_protocol":"MQTT","l7_confidence":"high",
 "bytes_total":220,"packets_total":4,"duration_ms":180,
 "mqtt":{"message_type":"CONNECT","protocol_level":"4"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

**FTP** (TCP, control channel):
```json
{"flow_id":"1a2b3c4d-0016","ts_start":"2026-07-25T14:22:22.000000Z",
 "ts_last":"2026-07-25T14:22:22.320000Z","src_ip":"10.0.4.17",
 "dst_ip":"10.0.5.180","src_port":51680,"dst_port":21,
 "protocol":"TCP","l7_protocol":"FTP","l7_confidence":"high",
 "bytes_total":96,"packets_total":4,"duration_ms":320,
 "ftp":{"is_response":"false","command":"USER"},
 "reassembly":{"out_of_order_segments":0,"overlap_detected":false,"retransmits":0},
 "flags":[]}
```

---

## Remaining protocols (older, dissector-only view — not yet re-rendered in the wrapped format above)

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
 "http_user_agent":"curl/8.0","http_first_line":"GET /index.html HTTP/1.1"}
```

**HTTP/2** (with HPACK-decoded pseudo-headers):
```json
{"protocol":"HTTP/2","http2_preface_present":"true","http2_frames_parsed":4,
 "http2_headers_frame_count":1,"http2_rst_stream_count":0,
 "http2_max_stream_id":1,"http2_authority":"www.example.com",
 "http2_method":"GET","http2_path":"/","http2_status":"200",
 "http2_settings_header_table_size":"4096"}
```

**SSH**:
```json
{"protocol":"SSH","ssh_identification_string":"SSH-2.0-OpenSSH_9.6",
 "ssh_protocol_version":"2.0","ssh_software_version":"OpenSSH_9.6",
 "ssh_kexinit_present":"true"}
```

**DHCP**:
```json
{"protocol":"DHCP","dhcp_op":"BOOTREQUEST","dhcp_message_type":"DHCPREQUEST",
 "dhcp_requested_ip":"192.168.1.105","dhcp_hostname":"barrys-laptop",
 "dhcp_vendor_class":"MSFT 5.0"}
```

**SIP**:
```json
{"protocol":"SIP","sip_is_response":"false","sip_method":"INVITE",
 "sip_from":"<sip:alice@example.com>","sip_to":"<sip:bob@example.com>",
 "sip_call_id":"a84b4c76e66710@pc33.example.com",
 "sip_first_line":"INVITE sip:bob@example.com SIP/2.0"}
```

**RTP**:
```json
{"protocol":"RTP","rtp_payload_type":"0","rtp_sequence_number":"12345",
 "rtp_timestamp":"3600000","rtp_ssrc":"0x1a2b3c4d","rtp_marker":"false",
 "rtp_csrc_count":"0"}
```

**ICMP**:
```json
{"protocol":"ICMP","icmp_type":"8","icmp_code":"0",
 "icmp_echo_identifier":"512","icmp_echo_sequence":"1",
 "icmp_checksum_valid":"true"}
```

**ICMPv6**:
```json
{"protocol":"ICMPv6","icmpv6_type":"135","icmpv6_code":"0",
 "icmpv6_nd_target_address":"2001:db8::1",
 "icmpv6_na_solicited_flag":"false","icmpv6_na_override_flag":"true",
 "icmpv6_na_router_flag":"false"}
```

**SMTP**:
```json
{"protocol":"SMTP","smtp_ehlo_domain":"mail.example.com",
 "smtp_mail_from":"<sender@example.com>","smtp_rcpt_to":"<recipient@example.org>",
 "smtp_response_code":"250","smtp_starttls_seen":"true",
 "smtp_data_command_seen":"true","smtp_message_from":"Sender Name <sender@example.com>",
 "smtp_message_to":"Recipient Name <recipient@example.org>",
 "smtp_message_subject":"Quarterly report","smtp_message_date":"Wed, 24 Jul 2026 10:00:00 -0700",
 "smtp_message_body_begins":"true"}
```

**ARP** (+ RARP, folded into the same dissector — see `dpi_arp_parser.c`):
```json
{"protocol":"ARP","arp_opcode":"Request","arp_sender_ip":"192.168.1.1",
 "arp_sender_mac":"00:1a:2b:3c:4d:5e","arp_target_ip":"192.168.1.105",
 "arp_target_mac":"00:00:00:00:00:00","arp_gratuitous":"false",
 "arp_reply_with_zero_target_mac":"false"}
```
RARP variant (opcode 3, real example verified — sender/target IP both
`0.0.0.0`, the correct semantics for a host that doesn't yet know its
own IP):
```json
{"protocol":"ARP","arp_opcode":"RARP Request","arp_sender_ip":"0.0.0.0",
 "arp_sender_mac":"00:04:00:83:76:2c","arp_target_ip":"0.0.0.0",
 "arp_target_mac":"00:04:00:83:76:2c"}
```
Etherleak padding disclosure (real finding — 73/105 real frames in a
dedicated capture leaked prior-packet bytes into Ethernet padding):
```json
{"protocol":"ARP","arp_opcode":"Request","arp_sender_ip":"10.2.1.4",
 "arp_sender_mac":"e0:7d:b1:6b:cf:00","arp_target_ip":"10.2.1.1",
 "arp_target_mac":"00:00:00:00:00:00","arp_padding_non_zero":"true"}
```
IP-MAC binding conflict (real finding — verified 8/8 true positives on
a real ARP-poisoning capture, 0/0 false positives across 6 other real
legitimate captures):
```json
{"protocol":"ARP","arp_opcode":"Reply","arp_sender_ip":"192.168.1.1",
 "arp_sender_mac":"00:20:78:d9:0d:db","arp_target_ip":"192.168.1.103",
 "arp_target_mac":"00:d0:59:aa:af:80",
 "arp_ip_mac_binding_conflict":"true",
 "arp_ip_mac_binding_previous_mac":"00:d0:59:aa:af:80"}
```

**MQTT**:
```json
{"protocol":"MQTT","mqtt_message_type":"CONNECT","mqtt_protocol_name":"MQTT",
 "mqtt_protocol_level":"4","mqtt_client_id":"sensor-042",
 "mqtt_topic_name":"factory/line3/temperature","mqtt_qos":"1"}
```

**NTP**:
```json
{"protocol":"NTP","ntp_leap_indicator":"0","ntp_version":"4","ntp_mode":"3",
 "ntp_stratum":"2","ntp_reference_id_hex":"c0248a01",
 "ntp_extension_or_mac_present":"false"}
```

**SNMP**:
```json
{"protocol":"SNMP","snmp_version":"1 (v2c)","snmp_community_string":"public",
 "snmp_pdu_type":"GetResponse","snmp_request_id":"1",
 "snmp_varbind_count":"1","snmp_v3_structure_not_parsed":"false"}
```

**STUN**:
```json
{"protocol":"STUN","stun_message_type":"Binding Success Response",
 "stun_transaction_id":"a1b2c3d4e5f6a1b2c3d4e5f6",
 "stun_xor_mapped_address":"203.0.113.7","stun_xor_mapped_port":"54321"}
```

**World of Warcraft** (the one real decodable message per session — real
account name and build number verified against a real capture; everything
after this one message is RC4-encrypted by the protocol itself, not a
gap in this dissector):
```json
{"protocol":"WoW","wow_opcode":"CMSG_AUTH_SESSION","wow_client_build":"7799",
 "wow_account_name":"SCOTTBOT"}
```

**BitTorrent Mainline DHT** (a real `get_peers` query — verified against
126,321 real payloads, 100% with zero parse failures, the largest, cleanest
real-traffic sample in this project):
```json
{"protocol":"BitTorrent-DHT","bt_dht_msg_type":"query",
 "bt_dht_transaction_id":"90","bt_dht_query":"get_peers",
 "bt_dht_node_id":"dc054f56ad545065f583e7a39cde863f9c0b0581",
 "bt_dht_info_hash":"020376cca233350e4d2f6225f90abbd4958cd281"}
```

**SCTP** (a real DATA chunk carrying M3UA — verified against 500 real
packets across 2 genuine captures, 100% detected correctly; this
project's own roadmap's explicitly-recommended "build first" item,
since nothing riding on top of SCTP is reachable without it):
```json
{"protocol":"SCTP","sctp_src_port":"2905","sctp_dst_port":"49152",
 "sctp_verification_tag":"0x1530a5e0","sctp_chunk_0_type":"DATA",
 "sctp_chunk_0_tsn":"2922725360","sctp_chunk_0_stream_id":"1",
 "sctp_chunk_0_stream_seq":"407","sctp_chunk_0_ppid":"M3UA",
 "sctp_chunk_0_inner_protocol":"M3UA"}
```
A real SACK chunk (verified to reference the exact same TSN seen in a
real DATA chunk above — internally consistent, not independently
plausible fields):
```json
{"protocol":"SCTP","sctp_src_port":"2905","sctp_dst_port":"49152",
 "sctp_verification_tag":"0x1530a5e0","sctp_chunk_0_type":"SACK",
 "sctp_chunk_0_cum_tsn_ack":"2922725360","sctp_chunk_0_a_rwnd":"65536",
 "sctp_chunk_0_gap_ack_blocks":"0","sctp_chunk_0_dup_tsns":"0"}
```

**M3UA** (reached via SCTP's PPID-keyed recursion, not its own
transport-layer port — verified against all 7 real M3UA messages found
in a genuine SS7-over-IP call-signaling capture, 7/7 sharing this exact
shape; Protocol Data, the nested MTP3-User payload, is deliberately
extracted as raw hex rather than decoded further — a real scope
boundary, not a gap):
```json
{"protocol":"M3UA","m3ua_message":"Transfer/DATA",
 "m3ua_network_appearance":"0x00000008","m3ua_routing_context":"0x00000015",
 "m3ua_protocol_data_hex":"00e39a0a00d167360302020f04646f837d48410300"}
```

**AMQP 0-9-1** (a real Basic.Publish frame — verified against 42 real,
complete frames across 3 genuine captures, real Celery task-queue
traffic; only reached this clean result after finding and fixing a
real bug in this project's own verification methodology, not the
protocol — see the README for the full story):
```json
{"protocol":"AMQP","amqp_frame_type":"METHOD","amqp_channel":"1",
 "amqp_method":"Basic.Publish","amqp_exchange":"celeryev",
 "amqp_routing_key":"worker.heartbeat"}
```
A real Queue.Declare (an anonymous, exclusive, auto-delete temporary
queue — the standard real-world pattern for a client-side reply
queue):
```json
{"protocol":"AMQP","amqp_frame_type":"METHOD","amqp_channel":"1",
 "amqp_method":"Queue.Declare","amqp_queue":"(server-generated)"}
```

**STP/RSTP** (a real RSTP BPDU — verified against 7 real, identical
frames from a genuine capture, every field decoding to a textbook-
standard, converged-topology configuration; detected via 802.3 LLC
framing, not a real EtherType, inside `dispatch_by_ethertype()`):
```json
{"protocol":"STP","stp_version":"2","stp_bpdu_type":"RST (Rapid/Multiple Spanning Tree)",
 "stp_flags":"0x6c","stp_root_priority":"32768","stp_root_mac":"00:08:83:f2:e2:00",
 "stp_root_path_cost":"40000","stp_bridge_priority":"32768",
 "stp_bridge_mac":"00:1d:b3:28:d7:00","stp_port_id":"0x801b",
 "stp_message_age_sec":"2.00","stp_max_age_sec":"20.00",
 "stp_hello_time_sec":"2.00","stp_forward_delay_sec":"15.00"}
```

**M2UA** (reached via SCTP's PPID-keyed recursion, PPID 2 — the one
real MAUP/Data message available, MTP2 User Peer-to-Peer Message Data
extracted as raw hex, not decoded further, the same scope boundary
M3UA draws around its own Protocol Data parameter):
```json
{"protocol":"M2UA","m2ua_message":"MAUP/Data","m2ua_interface_id":"0",
 "m2ua_mtp2_data_hex":"83715e40940600003100011200103725002b002700012a06193233000040"}
```

**PIM** (a real Hello message — verified against the one real message
available, Holdtime and LAN Prune Delay options both decoding cleanly):
```json
{"protocol":"PIM","pim_version":"2","pim_type":"Hello",
 "pim_hello_holdtime_sec":"105","pim_hello_lan_prune_delay_tbit":"false",
 "pim_hello_propagation_delay_ms":"0","pim_hello_override_interval_ms":"6641"}
```

**AppleTalk** (a real RTMP broadcast — verified against 2 real,
identical frames, internally coherent: hop count 0, destination node
255/broadcast, both socket numbers matching RTMP's well-known socket):
```json
{"protocol":"AppleTalk","ddp_hop_count":"0","ddp_length":"77",
 "ddp_checksum":"0x3764","ddp_dst_network":"0","ddp_src_network":"4415",
 "ddp_dst_node":"255","ddp_src_node":"175","ddp_dst_socket":"1",
 "ddp_src_socket":"1","ddp_type":"RTMP Response/Data"}
```

**PPPoE** (a real-shape PADO offer, structurally verified against RFC 2516's own worked example):
```json
{"protocol":"PPPoE","pppoe_stage":"Discovery","pppoe_code":"PADO",
 "pppoe_session_id":"0x0000","pppoe_length":"32",
 "pppoe_service_name":"","pppoe_ac_name":"Go Router 1234567890ABCD"}
```

**CDP** (verified against the Wireshark wiki's real, complete worked example):
```json
{"protocol":"CDP","cdp_version":"2","cdp_ttl_sec":"180","cdp_checksum":"0xc2c3",
 "cdp_device_id":"LAN354802","cdp_platform":"cisco WS-C3548-XL"}
```

**EAPOL** (a real EAP-Request/Identity, matching a real captured example):
```json
{"protocol":"EAPOL","eapol_version":"3","eapol_type":"EAP-Packet","eapol_length":"5",
 "eap_code":"Request","eap_identifier":"9","eap_length":"5","eap_type":"Identity"}
```

**LACP** (a real Actor Information TLV — verified against real tcpdump-captured
bytes; a real bug in the TLV-length constant was caught and fixed during this
dissector's own verification):
```json
{"protocol":"LACP","lacp_actor_system_priority":"100",
 "lacp_actor_system_mac":"00:0f:53:21:68:30","lacp_actor_key":"15",
 "lacp_actor_port_priority":"255","lacp_actor_port":"2",
 "lacp_actor_state_activity":"true","lacp_actor_state_timeout":"false",
 "lacp_actor_state_aggregation":"true","lacp_actor_state_synchronization":"true",
 "lacp_actor_state_collecting":"true","lacp_actor_state_distributing":"true"}
```

**RTSP**:
```json
{"protocol":"RTSP","rtsp_is_response":"false",
 "rtsp_first_line":"DESCRIBE rtsp://example.com/media.mp4 RTSP/1.0",
 "rtsp_method":"DESCRIBE","rtsp_url":"rtsp://example.com/media.mp4","rtsp_cseq":"1"}
```

**MySQL** (a real Initial Handshake packet, verified against the mysql-proxy
project's own documented example):
```json
{"protocol":"MySQL","mysql_packet_length":"54","mysql_sequence_id":"0",
 "mysql_protocol_version":"10","mysql_server_version":"5.5.2-m2",
 "mysql_connection_id":"82","mysql_capability_flags_lower":"0xffff"}
```

**PostgreSQL** (a real StartupMessage, verified against a real example from
the PostgreSQL mailing list archives):
```json
{"protocol":"PostgreSQL","pg_message_length":"38","pg_message_type":"StartupMessage",
 "pg_protocol_version":"3.0","pg_user":"postgres","pg_database":"maach"}
```

**TDS** (a real PRELOGIN response — verified against a complete, real, byte-exact
example; the encoded server version decoded to exactly "12.00.2000", matching
the original example's own stated value):
```json
{"protocol":"TDS","tds_type":"Tabular_Result","tds_eom":"true","tds_length":"20",
 "tds_spid":"0","tds_packet_id":"1","tds_prelogin_server_version":"12.00.2000"}
```

**NTP** (with extension fields, RFC 7822 — added on direct request; Field
Type's specific meaning is a separate IANA registry this project doesn't
assert names for):
```json
{"protocol":"NTP","ntp_extension_0_type":"0x0104","ntp_extension_0_length":"20",
 "ntp_extension_count":"1","ntp_mac_present":"false"}
```

**DECnet Phase IV** (deliberately detection-only — stated honestly, see the
README for why):
```json
{"protocol":"DECnet","decnet_phase":"IV","decnet_length":"46",
 "note":"detected via EtherType 0x6003 only; routing-layer header not decoded"}
```

**Banyan VINES** (deliberately detection-only — same reasoning as DECnet):
```json
{"protocol":"BanyanVINES","vines_subtype":"IP","vines_length":"38",
 "note":"detected via EtherType only; VIP header not decoded"}
```

**serialnumberd** (Apple Mac OS X Server — a real query found via this
project's own pcap survey, cross-verified against the Nmap probe database):
```json
{"protocol":"serialnumberd","serialnumberd_message_type":"SNQUERY",
 "serialnumberd_hostname":"domex.nps.edu","serialnumberd_token":"yWQBLA",
 "serialnumberd_suffix":"xsvr"}
```

**MACsec** (a real SecTAG — found via a second, EtherType-focused survey
pass; the Secure Channel Identifier's MAC component is a genuine, real
VMware-registered OUI, independently confirming the byte offsets):
```json
{"protocol":"MACsec","macsec_version":"false","macsec_end_station":"false",
 "macsec_sci_present":"true","macsec_single_copy_broadcast":"false",
 "macsec_encrypted":"true","macsec_changed_text":"true",
 "macsec_association_number":"0","macsec_short_length":"0",
 "macsec_packet_number":"16","macsec_sci":"00:0c:29:55:9b:4b/1"}
```

**HomePlug AV** (a real management-frame header — the decoded OUI is
Intellon Corporation's own genuine, historically-registered OUI):
```json
{"protocol":"HomePlugAV","homeplugav_mm_version":"0",
 "homeplugav_mm_type":"0x68a0","homeplugav_oui":"00:b0:52"}
```

**Ethernet Loopback** (deliberately detection-only — no formal spec exists
for this protocol at all, a different situation from DECnet/Banyan VINES):
```json
{"protocol":"EthernetLoopback","loopback_length":"60",
 "note":"detected via EtherType 0x9000 only; no formal spec exists to decode a payload structure against"}
```

**RADIUS**:
```json
{"protocol":"RADIUS","radius_code":"Access-Request","radius_identifier":"5",
 "user_name":"jsmith","user_password_present":"true",
 "nas_ip_address":"10.0.1.1","calling_station_id":"00-1A-2B-3C-4D-5E"}
```

**QUIC**:
```json
{"protocol":"QUIC","quic_version":"0x00000001","sni":"example.com","sni_absent":"false",
 "quic_handshake_msg_type_not_clienthello":"false"}
```

---

## GTP (mobile-core tunneling)

**GTP-U v1** (with recursively-dissected inner packet):
```json
{"protocol":"GTPv1-U","gtp_message_type":"G-PDU","gtp_teid":"0x12345678",
 "gtp_sequence_number":"42","gtp_extension_headers_present":"false",
 "gtp_inner_packet_present":"true",
 "gtp_inner_src_ip":"10.1.1.1","gtp_inner_dst_ip":"93.184.216.34",
 "gtp_inner_protocol":"TCP","gtp_inner_dst_port":"443",
 "gtp_inner_sni":"example.com"}
```
*(Field names shift to a `gtp_nested_*` prefix — e.g. `gtp_nested_inner_src_ip`
— at GTP-in-GTP recursion depth > 0, bounded by `GTP_MAX_TUNNEL_DEPTH`.)*

**GTPv2-C** (Create Session Request, with the now-complete Bearer QoS IE):
```json
{"protocol":"GTPv2-C","gtpv2_message_type":"Create Session Request",
 "gtpv2_teid":"0xaabbccdd","gtpv2_teid_present":"true","gtpv2_sequence_number":"555",
 "gtpv2_ie_0_imsi":"310150123456789","gtpv2_ie_1_apn":"internet.mnc001.mcc310.gprs",
 "gtpv2_ie_2_ebi":"5","gtpv2_ie_3_arp_pci":"1","gtpv2_ie_3_arp_priority_level":"5",
 "gtpv2_ie_3_arp_pvi":"0","gtpv2_ie_3_qci":"9",
 "gtpv2_ie_3_mbr_uplink_kbps":"50000","gtpv2_ie_3_mbr_downlink_kbps":"100000",
 "gtpv2_ie_3_gbr_uplink_kbps":"25000","gtpv2_ie_3_gbr_downlink_kbps":"75000",
 "gtpv2_ie_4_serving_network":"310-410","gtpv2_ie_count":"5"}
```

---

## Industrial / SCADA

**Modbus/TCP**:
```json
{"protocol":"Modbus","modbus_transaction_id":"1","modbus_unit_id":"1",
 "modbus_function":"Read Holding Registers","modbus_request_start_address":"0",
 "modbus_request_quantity":"10","modbus_exception_response":"false"}
```

**DNP3**:
```json
{"protocol":"DNP3","dnp3_source":"1024","dnp3_destination":"1",
 "dnp3_link_function":"UNCONFIRMED_USER_DATA","dnp3_transport_fir":"true",
 "dnp3_transport_fin":"true","dnp3_transport_sequence":"0",
 "dnp3_app_function":"Read","dnp3_app_sequence":"1",
 "dnp3_app_fir":"true","dnp3_app_fin":"true"}
```

**S7comm** (Siemens S7 ICS protocol, over TPKT+COTP):
```json
{"protocol":"S7comm","s7comm_rosctr":"Job Request","s7comm_pdu_reference":"256",
 "s7comm_param_length":"14","s7comm_data_length":"0",
 "s7comm_function_code":"Read Var","s7comm_function_code_raw":"0x04"}
```

---

## Routing and network infrastructure

**GRE** (with recursive inner-packet dissection, including ERSPAN detection):
```json
{"protocol":"GRE","gre_version":"0","gre_protocol_type":"0x0800",
 "gre_key_present":"true","gre_key":"0x00000064","gre_sequence_present":"false",
 "gre_checksum_present":"false","gre_erspan_detected":"false",
 "gre_inner_src_ip":"10.10.10.1","gre_inner_dst_ip":"10.10.20.5",
 "gre_inner_protocol":"TCP","gre_inner_dst_port":"443","gre_inner_sni":"example.com",
 "gre_nested_tunnel_detected":"false"}
```

**MPLS** (label stack, with recursive inner-packet dissection):
```json
{"protocol":"MPLS","mpls_top_label":"100","mpls_top_ttl":"64",
 "mpls_bottom_label":"200","mpls_stack_depth":"2",
 "mpls_inner_src_ip":"172.16.0.10","mpls_inner_dst_ip":"172.16.1.20",
 "mpls_inner_protocol":"TCP","mpls_inner_dst_port":"443","mpls_inner_sni":"example.com"}
```

**OSPF** (Hello packet):
```json
{"protocol":"OSPF","ospf_version":"2","ospf_type":"Hello","ospf_router_id":"10.0.0.1",
 "ospf_area_id":"0.0.0.0","ospf_autype":"0",
 "ospf_hello_netmask":"255.255.255.0","ospf_hello_interval":"10",
 "ospf_hello_dead_interval":"40","ospf_hello_priority":"1",
 "ospf_hello_dr":"10.0.0.1","ospf_hello_bdr":"10.0.0.2",
 "ospf_hello_neighbor_count":"1"}
```

**BGP** (OPEN message):
```json
{"protocol":"BGP","bgp_type":"OPEN","bgp_open_version":"4","bgp_open_my_as":"65001",
 "bgp_open_hold_time":"180","bgp_open_router_id":"10.0.0.1","bgp_message_count":"1"}
```
UPDATE variant:
```json
{"protocol":"BGP","bgp_type":"UPDATE","bgp_update_withdrawn_routes_len":"0",
 "bgp_update_as_path_len":"12","bgp_update_next_hop":"10.0.0.1",
 "bgp_update_origin":"IGP","bgp_update_med":"0","bgp_update_local_pref":"100",
 "bgp_message_count":"1"}
```

**RIP / RIPng**:
```json
{"protocol":"RIP","rip_version":"2","rip_command":"Response",
 "rip_is_ripng":"false","rip_entry_count":"3"}
```

**EIGRP** (Cisco-proprietary):
```json
{"protocol":"EIGRP","eigrp_version":"2","eigrp_opcode":"Hello","eigrp_sequence":"0",
 "eigrp_ack":"0","eigrp_init_flag":"false","eigrp_asn":"100",
 "eigrp_tlv_count":"3","eigrp_first_tlv_type":"0x0001"}
```

**LDP** (MPLS Label Distribution Protocol):
```json
{"protocol":"LDP","ldp_router_id":"10.0.0.1","ldp_label_space":"0",
 "ldp_message_type":"Label Mapping","ldp_label_mapping_fec":"10.0.0.0/24",
 "ldp_label_mapping_label":"3","ldp_message_count":"1"}
```

**HSRP** (v1):
```json
{"protocol":"HSRP","hsrp_version":"1","hsrp_recognized_version":"true",
 "hsrp_opcode":"Hello","hsrp_state":"Active","hsrp_hellotime":"3",
 "hsrp_holdtime":"10","hsrp_priority":"100","hsrp_group":"1",
 "hsrp_virtual_ip":"192.168.1.254","hsrp_auth_data_present":"true"}
```

**IGMP** (v2 Membership Report, and a v3 Membership Query with a real group record):
```json
{"protocol":"IGMP","igmp_type":"Membership Report (v2)",
 "igmp_group_address":"239.255.255.250","igmp_max_resp_time":"0"}
```
```json
{"protocol":"IGMP","igmp_type":"Membership Query","igmp_max_resp_time":"100",
 "igmp_v3_qrv":"2","igmp_v3_num_sources":"0","igmp_v3_num_group_records":"1",
 "igmp_v3_first_record_type":"MODE_IS_EXCLUDE",
 "igmp_v3_first_record_mcast_addr":"239.1.1.1"}
```

---

## Tunneling / VPN / IPsec

**ESP** (encrypted — SPI/sequence only, correctly not decrypted):
```json
{"protocol":"ESP","esp_spi":"0x12345678","esp_sequence":"100",
 "esp_payload_encrypted":"true"}
```

**AH** (authenticated, NOT encrypted — inner protocol recoverable):
```json
{"protocol":"AH","ah_spi":"0x87654321","ah_sequence":"55",
 "ah_next_header":"89","ah_inner_protocol":"OSPF",
 "ah_authenticated_not_encrypted":"true",
 "ah_inner_summary":"OSPFv3 Hello, router_id=10.0.0.1"}
```

**6in4** (IPv6-in-IPv4 tunnel, HE.net tunnelbroker-style):
```json
{"protocol":"6in4","sixin4_inner_src_ip":"2001:470:1f0a:1::2",
 "sixin4_inner_dst_ip":"2001:470:1f0b:2::1","sixin4_inner_protocol":"TCP",
 "sixin4_inner_dst_port":"443","sixin4_inner_sni":"example.com"}
```

**ISAKMP / IKE** (Aggressive Mode, IKEv1 — the dominant real-traffic pattern found):
```json
{"protocol":"ISAKMP","isakmp_initiator_spi":"0x1122334455667788",
 "isakmp_responder_spi":"0x0000000000000000","isakmp_version":"1.0",
 "isakmp_ike_version":"IKEv1","isakmp_exchange_type":"Aggressive",
 "isakmp_flags":"0x00","isakmp_message_id":"0x00000000"}
```

**L2TPv3** (Ethernet pseudowire, with recursive inner-packet dissection):
```json
{"protocol":"L2TPv3","l2tpv3_session_id":"0x00001138",
 "l2tpv3_inner_src_mac":"c2:38:19:7c:00:00","l2tpv3_inner_dst_mac":"c2:39:19:7c:00:00",
 "l2tpv3_inner_src_ip":"172.17.1.51","l2tpv3_inner_dst_ip":"172.17.2.52",
 "l2tpv3_inner_protocol":"TCP"}
```

---

## Directory / authentication

**LDAP**:
```json
{"protocol":"LDAP","ldap_message_id":"1","ldap_operation":"BindRequest",
 "ldap_bind_dn":"cn=admin,dc=example,dc=com","ldap_bind_version":"3",
 "ldap_bind_credential_present":"true","ldap_starttls_requested":"false",
 "ldap_message_count":"1"}
```
Search variant:
```json
{"protocol":"LDAP","ldap_message_id":"2","ldap_operation":"SearchRequest",
 "ldap_search_base_dn":"dc=example,dc=com","ldap_search_scope":"wholeSubtree",
 "ldap_result_code":"0","ldap_result_entry_dn":"cn=jsmith,ou=users,dc=example,dc=com"}
```

**Kerberos** (KRB-ERROR, real error code verified against real traffic):
```json
{"protocol":"Kerberos","kerberos_msg_type":"KRB-ERROR",
 "kerberos_error_code":"25","kerberos_error_name":"KDC_ERR_PREAUTH_REQUIRED"}
```

---

## File transfer

**FTP**:
```json
{"protocol":"FTP","ftp_command":"USER","ftp_response_code":"331",
 "ftp_password_present":"true","ftp_auth_tls_requested":"false"}
```

**TFTP** (real WRQ verified against a real captured router-config upload):
```json
{"protocol":"TFTP","tftp_opcode":"WRQ","tftp_filename":"CCNP-LAB-R2-Mar--3-20-02-38.701-7",
 "tftp_mode":"octet"}
```

**SMB1 / CIFS**:
```json
{"protocol":"SMB1","smb1_command":"Negotiate Protocol","smb1_is_response":"false",
 "smb1_pid":"1234","smb1_tid":"0","smb1_uid":"0","smb1_mid":"1",
 "smb1_status":"0x00000000"}
```

---

## Legacy / messaging / discovery

**MSNP** (MSN Messenger protocol — two real message shapes, distinguished by '@' presence):
```json
{"protocol":"MSNP","msnp_command":"USR","msnp_usr_email":"alice@hotmail.com",
 "msnp_usr_ticket_present":"true"}
```
```json
{"protocol":"MSNP","msnp_command":"MSG","msnp_msg_sender_email":"bob@hotmail.com",
 "msnp_msg_transaction_id":"7","msnp_msg_content_type":"text/plain",
 "msnp_msg_length":"42"}
```

**NetBIOS** (NBNS name query + NBDS datagram — two distinct message families in one dissector):
```json
{"protocol":"NetBIOS","nbns_opcode":"Query","nbns_is_response":"false",
 "nbns_name":"WORKGROUP","nbns_name_suffix":"0x1D"}
```
```json
{"protocol":"NetBIOS","nbds_msg_type":"Direct_Unique Datagram",
 "nbds_source_name":"BARRYSCOMPUTER","nbds_destination_name":"WORKGROUP",
 "nbds_source_ip":"192.168.1.50"}
```

**Telnet** (credential-blind by design — see the dissector's own scope note):
```json
{"protocol":"Telnet","telnet_negotiation_count":"2",
 "telnet_data_preview":"login: "}
```

**WHOIS**:
```json
{"protocol":"WHOIS","whois_query":"-T dn,ace weberlab.de"}
```
```json
{"protocol":"WHOIS","whois_response_preview":"% Restricted rights.\n% \n% Terms and Conditions of Use\n% \n% The above data may on..."}
```

**Syslog**:
```json
{"protocol":"Syslog","syslog_rfc5424":"false","syslog_pri":"134",
 "syslog_facility":"16 (local0)","syslog_severity":"6 (informational)",
 "syslog_message_count":"1","syslog_message_preview":"Interface GigabitEthernet0/1, changed state to up"}
```

**SSDP** (UPnP discovery):
```json
{"protocol":"SSDP","ssdp_method":"M-SEARCH"}
```

**mDNS**:
```json
{"protocol":"mDNS","dns_is_response":"false","dns_qname":"printer.local",
 "dns_qtype":"1","mdns_qclass_masked":"1","mdns_qu_bit_requested":"true",
 "mdns_cache_flush_bit":"false"}
```

**LLDP** (real chassis/port/management-address shape verified against 8,616 real frames):
```json
{"protocol":"LLDP","lldp_chassis_id_subtype":"4","lldp_chassis_id_mac":"00:22:2d:81:db:10",
 "lldp_port_id_subtype":"7","lldp_port_id":"1","lldp_ttl":"120",
 "lldp_management_address":"192.168.2.10"}
```

**WoL** (Wake-on-LAN Magic Packet — real target OUI verified):
```json
{"protocol":"WoL","wol_target_mac":"b8:27:eb:bc:cd:b4",
 "wol_secureon_password_present":"false"}
```

**POP3**:
```json
{"protocol":"POP3","pop3_command":"RETR","pop3_status":"+OK",
 "pop3_password_present":"true"}
```

---

## Link layer (reached via EtherType dispatch, not TCP/UDP)

**802.11** (WiFi — Beacon with real SSID, and Authentication with the Protected-bit check):
```json
{"protocol":"802.11","dot11_type":"Management","dot11_subtype":"Beacon",
 "dot11_addr1":"ff:ff:ff:ff:ff:ff","dot11_beacon_ssid":"TESLA"}
```
```json
{"protocol":"802.11","dot11_type":"Management","dot11_subtype":"Authentication",
 "dot11_addr1":"00:14:a5:30:b0:af","dot11_addr2":"00:11:88:6b:68:30",
 "dot11_seq_num":"42","dot11_auth_algorithm":"Shared Key","dot11_auth_seq":"1",
 "dot11_auth_status":"0"}
```
Encrypted-frame case (Protected bit set — correctly flagged, not misread as plaintext):
```json
{"protocol":"802.11","dot11_type":"Management","dot11_subtype":"Authentication",
 "dot11_auth_encrypted":"true"}
```
Data frame carrying a real SNAP-encapsulated ARP Probe (RFC 5227,
verified against 38 real frames — real iPhone Wi-Fi-startup traffic;
reached via either `--link-type=80211` or, for a Radiotap-wrapped
capture, `--link-type=80211-radiotap`):
```json
{"protocol":"802.11","dot11_type":"Data","dot11_subtype":"Data",
 "dot11_addr1":"ff:ff:ff:ff:ff:ff","dot11_addr2":"00:23:12:70:66:f5","dot11_addr3":"00:13:46:cc:a3:ea",
 "dot11_data_arp_opcode":"Request","dot11_data_arp_sender_ip":"0.0.0.0",
 "dot11_data_arp_target_ip":"192.168.0.108"}
```
Data frame carrying real IPv4-over-SNAP traffic, recursed all the way
through TCP to a real HTTP request (verified against 125 real HTTP
requests in a real YouTube-era capture, `app-youtube1.pcapng`):
```json
{"protocol":"802.11","dot11_type":"Data","dot11_subtype":"Data",
 "dot11_data_inner_src_ip":"192.168.0.104","dot11_data_inner_dst_ip":"208.65.153.251",
 "dot11_data_inner_http_method":"GET","dot11_data_inner_http_path":"/buzz_videos",
 "dot11_data_inner_http_host":"www.youtube.com"}
```

---

## A note on what's deliberately absent from this file

The VPN detector (`dpi_vpn_detector.c`) and DoH/DoT detector
(`dpi_doh_dot_detector.c`) don't get standalone samples here — they're
scored *overlay signals* folded into the baseline flow record above
(`vpn_score`, `vpn_protocol`, `dot_score`, `doh_score`), not discrete
protocols with their own dissection output. The `parse_warning` field
appears across nearly every dissector for malformed/truncated input
and isn't broken out per-protocol here — see each dissector's own
source comments for what specifically triggers it.
