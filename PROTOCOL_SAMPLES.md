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
complete one. 69 samples, covering all 53 `protocols.ini` entries plus
the baseline flow record, 802.11 (standalone, not `protocols.ini`-
gated), and RARP (folded into ARP, same dissector).

---

## Baseline flow record (every packet, before any protocol-specific dissection)

**IPv4 + TCP + TLS/SNI**:
```json
{"src_ip":"10.0.4.17","dst_ip":"157.240.22.35","src_port":51422,"dst_port":443,
 "sni":"instagram.com","category":"social_media","app_name":"Instagram",
 "confidence":"high","dga_score":0.06,"vpn_score":0.0,"vpn_protocol":"none",
 "dot_score":0.0,"doh_score":0.0,
 "reassembly":{"out_of_order":0,"retransmits":1,"overlap_conflicts":0,"evasion_flag":false}}
```

**IPv6 + TCP**:
```json
{"src_ip":"2001:db8::1","dst_ip":"2606:2800:220:1:248:1893:25c8:1946",
 "src_port":54210,"dst_port":443,"sni":"example.com","category":"unclassified",
 "confidence":"low","dga_score":0.03,"vpn_score":0.0,"vpn_protocol":"none",
 "dot_score":0.0,"doh_score":0.0,
 "reassembly":{"out_of_order":0,"retransmits":0,"overlap_conflicts":0,"evasion_flag":false}}
```

---

## Core application protocols

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
