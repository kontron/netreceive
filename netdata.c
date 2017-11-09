/****************************************************************************
 *  Traffic Analyzer: Analyzis of ethernet packet data
 *
 *  Currently the anylysis extracts:
 *        Ethernet Type
 *        UDP destination port
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <glib.h>

#include "netdata.h"

/*--------------------------------------------------------------------------
 * protocol structures
 *------------------------------------------------------------------------*/

/* Ethernet header */
struct ether_hdr_s {
    guint8  dhost[6];
    guint8  shost[6];
    guint16 ether_type;
};

/* Ethernet header with VLAN tag */
struct ether_vlan_hdr_s {
    guint8   dhost[6];
    guint8   shost[6];
    guint16  tpid;        /*Tag Protocol Identifier*/
    guint16  tci;         /*Tag Control Information (includes VID)*/
    guint16  ether_type;
};

#define ETHER_TYPE_IP         0x0800
#define ETHER_TYPE_802_1Q     0x8100
#define ETHER_TYPE_802_1AD    0x88A8

/* IP header */
struct ip_hdr_s {
    guint8  hdrlength_version;
    guint8  tos;
    guint16 length;
    guint16 id;
    guint16 offset;
    guint8  ttl;
    guint8  protocol;
    guint16 chksum;
    guint32 srcip;
    guint32 dstip;
};

#define IP_HEADER_LEN(opt_len) ((20 + opt_len)/4)

#define IP_PROTOCOL_UDP  17

/* UDP header */
struct udp_hdr_s {
    guint16 sport;
    guint16 dport;
    guint16 length;
    guint16 chksum;
};

/*--------------------------------------------------------------------------
 *  IP / UDP
 *------------------------------------------------------------------------*/

static void analyze_udp_packet (protodata_t* pInfo, const guint8* pp,
                                guint32 len)
{
    struct udp_hdr_s* pUdp;

    if (len < sizeof(struct udp_hdr_s)) {
        /* packet too short - ignore */
        return;
    }

    pUdp = (struct udp_hdr_s*) pp;
    pInfo->exist      |= PROTO_UDP_DPORT;
    pInfo->udpDestPort = ntohs(pUdp->dport);

    pp  += sizeof(struct udp_hdr_s);
    len -= sizeof(struct udp_hdr_s);
}

static void analyze_ip_packet (protodata_t* pInfo, const guint8* pp,
                               guint32 len)
{
    struct ip_hdr_s* pIp;
    gint             hdrSize;
    //guint16        chksum;

    pIp = (struct ip_hdr_s *) pp;
    if (len < sizeof (struct ip_hdr_s)) {
        /* packet too short - ignore */
        return;
    }

    pp  += sizeof(struct ip_hdr_s);
    len -= sizeof(struct ip_hdr_s);

    hdrSize = (int)(pIp->hdrlength_version & 0x0f); /*32-bit words*/

    /* check checksum (length in 16-bit words) */
    // chksum = ip->chksum;
    // ip->chksum = 0;
    // if (IP_chksum(ip, (hdr_size * 2)) != chksum ) {
    //     printf("IP checksum error\n");
    // }

    /* IP options */
    int optionLen;
    optionLen = hdrSize - IP_HEADER_LEN(0);
    pp  += (optionLen * 4);
    len -= (optionLen * 4);

    /* analyze UDP protocol if available */
    if (pIp->protocol == IP_PROTOCOL_UDP) {
        analyze_udp_packet (pInfo, pp, len);
    }
}

/*--------------------------------------------------------------------------
 *  Ethernet
 *------------------------------------------------------------------------*/

static gboolean is_vlan_ether_type (guint16 ethType)
{
    return ((ethType == ETHER_TYPE_802_1Q) || (ethType == ETHER_TYPE_802_1Q));
}

void analyze_eth_packet (protodata_t* pInfo, const guint8 *packet,
                         guint32 packetLength)
{
    struct ether_hdr_s* pEth;
    guint16             ethType;
    const guint8*       pp  = packet;
    guint32             len = packetLength;

    memset(pInfo, 0, sizeof(*pInfo));

    /* Analyze ethernet header */

    /* packets without complete ethernet header are ignored */
    if (len < sizeof (struct ether_hdr_s)) {
        return;
    }

    pEth    = (struct ether_hdr_s*) pp;
    ethType = ntohs(pEth->ether_type);

    /* check for VLAN tag */
    if (is_vlan_ether_type(ethType)) {
        struct ether_vlan_hdr_s* pEthVlan;
        //guint8                 vlanPrio;

        pEthVlan = (struct ether_vlan_hdr_s*) pp;
        ethType  = ntohs(pEthVlan->ether_type);
        //vlanPrio = ((((guint8*) &pEthVlan->tci)[0]) >> 5);

        pp  += sizeof(struct ether_hdr_s);
        len -= sizeof(struct ether_hdr_s);

        /* double vlan tag */
        if (is_vlan_ether_type(ethType)) {
            pp += 2;
            ethType = ntohs(*((uint16_t*) pp));
            pp += 2;
            len -= 5;
        }
    }
    else {
        pp  += sizeof(struct ether_hdr_s);
        len -= sizeof(struct ether_hdr_s);
    }

    pInfo->exist  |= PROTO_ETH_TYPE;
    pInfo->ethType = ethType;

    /* Analyze IP packet if available */

    if (ethType == ETHER_TYPE_IP) {
        analyze_ip_packet (pInfo, pp, len);
    }
}
/* (end-of-file) */
