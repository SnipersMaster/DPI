/*
 * dpi_vlan_parser.c
 *
 * 802.1Q (RFC / IEEE 802.1Q) VLAN tag stripping, including 802.1ad
 * ("QinQ", double-tagged) frames. This is a framing-layer helper, not
 * a protocol dissector in the detect()/dissect() sense — there's no
 * "VLAN traffic" to classify the way there's HTTP or DNS traffic;
 * every frame either has VLAN tags or doesn't, and this just strips
 * them so the EXISTING ethertype dispatch (IPv4/IPv6/ARP) in both
 * capture files sees the real inner ethertype and payload, unchanged.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * WHY THIS WAS MISSING BEFORE, AND WHY IT'S A REAL GAP TO CLOSE
 * -------------------------------------------------------------------
 * Neither capture path previously checked for ethertype 0x8100
 * (802.1Q) or 0x88A8 (802.1ad outer tag) at all — a VLAN-tagged frame's
 * first ethertype field would read as one of those values, match none
 * of the existing IPV6/ARP/IPV4 branches, and get silently dropped.
 * VLAN trunking is extremely common in real deployments (most
 * enterprise/carrier switched networks use 802.1Q somewhere), so this
 * wasn't a corner case — it was a real, current blind spot for
 * anything downstream of a trunk port.
 *
 * WIRE FORMAT (IEEE 802.1Q clause 9.6): right where the Ethernet
 * header's EtherType field normally is, a tagged frame instead has:
 *   TPID (2 bytes) = 0x8100 (802.1Q) or 0x88A8 (802.1ad, QinQ outer)
 *   TCI  (2 bytes) = PCP(3 bits) + DEI/CFI(1 bit) + VID(12 bits)
 *   [the REAL EtherType follows, then the payload]
 * A double-tagged (QinQ) frame has TWO such 4-byte tag blocks back to
 * back (outer 0x88A8 tag, then inner 0x8100 tag) before the real
 * EtherType.
 *
 * BOUNDED TO 2 LEVELS OF TAGGING — same safety reasoning as every
 * other bounded-recursion/bounded-nesting decision in this project
 * (GTP-in-GTP's GTP_MAX_TUNNEL_DEPTH, DNS's MAX_POINTER_JUMPS): two
 * levels covers every real QinQ deployment; an attacker-crafted frame
 * claiming more nested tags than that is rejected rather than walked
 * indefinitely. Real 802.1Q/802.1ad deployments essentially never
 * exceed 2 levels — triple-tagging exists in theory but not in
 * practice — so this bound costs nothing for legitimate traffic.
 */

#include <stdint.h>
#include <stdbool.h>

#define ETHERTYPE_8021Q  0x8100   /* 802.1Q single tag */
#define ETHERTYPE_8021AD 0x88A8   /* 802.1ad, QinQ outer tag */
#define VLAN_TAG_LEN     4        /* TCI(2) + inner EtherType(2), TPID
                                     already consumed as "ethertype" by
                                     the caller before this is invoked */
#define VLAN_MAX_TAGS    2        /* bound, see file header comment */

struct vlan_strip_result {
    uint16_t real_ethertype;     /* the actual EtherType after all VLAN
                                     tags are stripped — IPv4/IPv6/ARP/
                                     etc., whatever the caller's existing
                                     dispatch already checks for */
    const uint8_t *payload;      /* pointer past all stripped tags */
    uint16_t payload_len;
    int      n_tags_stripped;    /* 0, 1, or 2 */
    uint16_t vlan_id_outer;      /* valid only if n_tags_stripped >= 1 */
    uint16_t vlan_id_inner;      /* valid only if n_tags_stripped == 2 */
};

/*
 * `first_ethertype` is the ethertype the caller already read (the
 * field immediately after the source MAC) — passed in rather than
 * re-read here since both capture paths already extract it before any
 * dispatch decision. `payload`/`payload_len` is everything AFTER that
 * ethertype field. Returns false if the frame claims to be VLAN-tagged
 * but doesn't have enough bytes for the tags it claims — caller should
 * drop the frame in that case, same as any other malformed-frame path
 * in this project.
 */
static bool vlan_strip(uint16_t first_ethertype, const uint8_t *payload, uint16_t payload_len,
                        struct vlan_strip_result *out) {
    out->n_tags_stripped = 0;
    out->vlan_id_outer = 0;
    out->vlan_id_inner = 0;

    uint16_t ethertype = first_ethertype;
    const uint8_t *pos = payload;
    uint16_t remaining = payload_len;

    while ((ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) &&
           out->n_tags_stripped < VLAN_MAX_TAGS) {
        if (remaining < VLAN_TAG_LEN) return false;   /* claims a tag, doesn't have one: malformed */

        uint16_t tci = (pos[0] << 8) | pos[1];
        uint16_t vid = tci & 0x0FFF;   /* low 12 bits — PCP/DEI occupy the top 4 */

        if (out->n_tags_stripped == 0) {
            out->vlan_id_outer = vid;
        } else {
            out->vlan_id_inner = vid;
        }
        out->n_tags_stripped++;

        uint16_t next_ethertype = (pos[2] << 8) | pos[3];
        pos += VLAN_TAG_LEN;
        remaining -= VLAN_TAG_LEN;
        ethertype = next_ethertype;
    }

    if (ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) {
        /* Still looks tagged after VLAN_MAX_TAGS strips — either a
         * frame with more nesting than any real deployment uses, or an
         * attacker probing for unbounded-nesting behavior. Reject
         * rather than keep walking, same as GTP-in-GTP's depth bound. */
        return false;
    }

    out->real_ethertype = ethertype;
    out->payload = pos;
    out->payload_len = remaining;
    return true;
}
