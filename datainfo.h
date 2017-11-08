/*
 *  (c) Copyright 2014 Kontron Europe GmbH, Saarbruecken
 */

/*
 * Test data generator and reciver common definitions
 *
 */

#ifndef TEST_DATA_H_INCLUDED
#define TEST_DATA_H_INCLUDED

#include <stdint.h>

struct valstr {
    uint16_t val;
    const char * str;
};


const char * val_2_string(int val, const void *vs);

/*-------------------- TCP header ------------------------------------------*/

struct mcl_tcphdr
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset;
    uint8_t  flags;
    uint16_t win;
    uint16_t chksum;
    uint16_t urgp;
};
#define mcl_tcphdr_n2h(tcp) do \
{\
    tcp->sport  = ntohs (tcp->sport);\
    tcp->dport  = ntohs (tcp->dport);\
    tcp->seq    = ntohl (tcp->seq);\
    tcp->ack    = ntohl (tcp->ack);\
    tcp->win    = ntohs (tcp->win);\
    tcp->chksum = ntohs (tcp->chksum);\
    tcp->urgp   = ntohs (tcp->urgp);\
} while (0)

/*-------------------- UDP header ------------------------------------------*/

struct mcl_udphdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t chksum;
};
#define mcl_udphdr_n2h(udp) do \
{\
    udp->sport  = ntohs (udp->sport);\
    udp->dport  = ntohs (udp->dport);\
    udp->length = ntohs (udp->length);\
    udp->chksum = ntohs (udp->chksum);\
} while (0)

enum {
    MCL_UDP_PORT_BOOTPS = 67,
    MCL_UDP_PORT_BOOTPC = 68,
    MCL_UDP_PORT_NTP    = 123,
    MCL_UDP_PORT_RIP    = 520,
    MCL_UDP_PORT_SFLOW  = 6343
};

/*-------------------- IPv6 header ----------------------------------------*/
struct mcl_ip6hdr
{
    uint32_t hdrversion_tc_fl;
    uint16_t length;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    uint8_t  srcip[16];
    uint8_t  dstip[16];
};

enum {
    MCL_IP6_NEXT_HDR_HOP_BY_HOP  = 0,
    MCL_IP6_NEXT_HDR_IPIP        = 4,
    MCL_IP6_NEXT_HDR_TCP         = 6,
    MCL_IP6_NEXT_HDR_EGP         = 8,
    MCL_IP6_NEXT_HDR_UDP         = 17,
    MCL_IP6_NEXT_HDR_ROUTING     = 43,
    MCL_IP6_NEXT_HDR_FRAGMENT    = 44,
    MCL_IP6_NEXT_HDR_ESP         = 50,
    MCL_IP6_NEXT_HDR_AH          = 51,
    MCL_IP6_NEXT_HDR_ICMP6       = 58,
    MCL_IP6_NEXT_HDR_NONE        = 59,
    MCL_IP6_NEXT_HDR_DESTINATION = 60,
    MCL_IP6_NEXT_HDR_OSPF        = 89,
    MCL_IP6_NEXT_HDR_PIM         = 103,
    MCL_IP6_NEXT_HDR_VRRP        = 112,
    MCL_IP6_NEXT_HDR_EXPERIMENT  = 253
};

#define MCL_IP6_VERSION         6
#define MCL_IP6_TRAFFIC_CLASS   0
#define MCL_IP6_FLOW_LABEL      0
#define MCL_IP6_HOP_LIMIT      30

#define MCL_IP6_OPTION_PAD1     0
#define MCL_IP6_OPTION_PADN     1
#define MCL_IP6_OPTION_RT_ALERT 5

/*-------------------- IP header ------------------------------------------*/

struct mcl_iphdr
{
    uint8_t  hdrlength_version;
    uint8_t  tos;
    uint16_t length;
    uint16_t id;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t chksum;
    uint32_t srcip;
    uint32_t dstip;
} __attribute__((packed));

enum {
    MCL_IP_PROTOCOL_ICMP       = 1,
    MCL_IP_PROTOCOL_IGMP       = 2,
    MCL_IP_PROTOCOL_IPIP       = 4,
    MCL_IP_PROTOCOL_TCP        = 6,
    MCL_IP_PROTOCOL_UDP        = 17,
    MCL_IP_PROTOCOL_OSPF       = 89,
    MCL_IP_PROTOCOL_PIM        = 103,
    MCL_IP_PROTOCOL_VRRP       = 112,
    MCL_IP_PROTOCOL_EXPERIMENT = 253  /*used for experimentation and testing*/
};

#define MCL_IP_HEADERLEN(opt_len) ((20 + opt_len)/4)
#define MCL_IP_VERSION       4
#define MCL_IP_TTL           30   /*default value for TTL*/
#define MCL_IP_TOS           0    /*default value for TOS*/

#define MCL_OFFSET_MASK      0x1fff
#define MCL_FLAG_FRAGMENT    0x4000
#define MCL_FLAG_FRAGM_MORE  0x2000

#define mcl_iphdr_n2h(ip) do \
{\
    ip->length = ntohs (ip->length);\
    ip->id     = ntohs (ip->id);\
    ip->offset = ntohs (ip->offset);\
    ip->chksum = ntohs (ip->chksum);\
    ip->srcip  = ntohl (ip->srcip);\
    ip->dstip  = ntohl (ip->dstip);\
} while (0)

/*-------------------- Ethernet header --------------------------------------*/

struct mcl_ether  {
    uint8_t  dhost[6];
    uint8_t  shost[6];
    uint16_t ether_type;
};

    /*Note: the struct "mcl-ether" is padded to 4 bytes (=16)*/
#define ETHER_HDR_LENGTH      14   /*length of pure ethernet header  */
                                   /*length of tagged ethernet header*/
#define ETHER_TAG_HDR_LENGTH  (ETHER_HDR_LENGTH + 4)

#define MCL_ETHER_MIN_DATA_LEN    46  /*minimal data length*/
#define MCL_ETHER_MAX_DATA_LEN  1500  /*maximal data length*/

/* see https://en.wikipedia.org/wiki/EtherType */
#define MCL_ETHER_TYPE_IP          0x0800
#define MCL_ETHER_TYPE_ARP         0x0806
#define MCL_ETHER_TYPE_TESTING     0x0808
#define MCL_ETHER_TYPE_TESTING_1   0x0809
#define MCL_ETHER_TYPE_TESTING_2   0x080a
#define MCL_ETHER_TYPE_TESTING_3   0x080b
#define MCL_ETHER_TYPE_IPX         0x8137
#define MCL_ETHER_TYPE_IP6         0x86DD
#define MCL_ETHER_TYPE_SLOW_PROTO  0x8809
#define MCL_ETHER_TYPE_MPLS        0x8847
#define MCL_ETHER_TYPE_LLDP        0x88CC
#define MCL_ETHER_TYPE_LOOPBACK    0x9000



#define MCL_ETHER_BCAST_ADDR      "ff:ff:ff:ff:ff:ff"

/* Ethernet header with VLAN tag */
struct mcl_vlan
{
    uint8_t   dhost[6];
    uint8_t   shost[6];
    uint16_t  tpid;        /*Tag Protocol Identifier*/
    uint16_t  tci;         /*Tag Control Information (includes VID)*/
    uint16_t  ether_type;
};

#define TPID_802_1Q_ETHERNET    0x8100
#define TPID_802_1AD_ETHERNET   0x88A8

#define TCI_PRIORITY                 0   /*default value*/

/*-------------------- Ethernet packet with testdata ------------------------*/

#define TESTDATA_PACKET_TAG 0xF67EABC9
struct testdata_packet
{
        /* CRC32 computed using test_crc32 function over data and header */
    uint32_t crc32;
        /* special tag to identify the packet header */
    uint32_t tag;
        /* size of packet data including this structure */
    uint32_t payload_size;
        /* second.microsecond timestamp of sender */
    struct timeval timestamp;
        /* monotonic packet counter of sender */
    uint32_t serialno;
        /* first byte of data in packet */
    //char data[1];
    uint8_t data[1];
};

struct eth_testdata_packet
{
    struct mcl_ether        eth;
    struct testdata_packet  data;
};

/* Ethernet header inclusive ethernet coded VLAN tag*/
struct vlan_testdata_packet
{
    struct mcl_vlan        eth_vlan;
    struct testdata_packet data;
};

/*-------------------------- LLC/GARP/BPDU/LACP protocol data --------------*/

/*LLC protocol information*/
#define SAP_SPANNING_TREE        0x42
#define LLC_UI_COMMAND           0x03

/*GARP protocol information*/
#define GARP_PROTOCOL_ID         0x0001
#define GARP_EVENT_LEAVE_ALL        0
#define GARP_EVENT_JOIN_IN          2

#define GMRP_MCAST_ETH_ADDR    "\x01\x80\xc2\x00\x00\x20"
#define GMRP_GROUP_ATTR             1
#define GMRP_GROUP_SERVICE_REQ      2

#define GVRP_MCAST_ETH_ADDR    "\x01\x80\xc2\x00\x00\x21"
#define GVRP_GROUP_ATTR             1

/*BPDU protocol information*/
#define STP_MCAST_ETH_ADDR     "\x01\x80\xc2\x00\x00\x00"
#define STP_PROTOCOL_ID          0x0000

/*LACP protocol information*/
#define LACP_MCAST_ETH_ADDR    "\x01\x80\xc2\x00\x00\x02"
#define SUBTYPE_LACP            0x01
#define LACP_VERSION            0x01

/*LLDP protocol information*/
#define LLDP_MCAST_ETH_ADDR    "01:80:C2:00:00:0E"

/*BPDU protocol structure*/
/*NOTE: only part of the data can be used in a structure because
        alignment to 32 bytes partially*/

struct brg_id
{
    uint16_t prio;         /* priority                */
    uint8_t  id[6];        /* id = MAC address        */
};

struct proto_bpdu
{
    struct brg_id  root_id;       /* Root bridge-ID         */
    uint32_t       path_cost;     /* path cost to Root      */
    struct brg_id  bridge_id;     /* current bridge-ID      */
    uint8_t        port_id[2];    /* current port-ID        */
    uint16_t       message_age;
    uint16_t       max_age;
    uint16_t       hello_time;
    uint16_t       fwd_delay;
};

#define proto_bpdu_n2h(bpdu) do \
{\
    bpdu->root_id.prio   = ntohs (bpdu->root_id.prio);\
    bpdu->path_cost      = ntohl (bpdu->path_cost);\
    bpdu->bridge_id.prio = ntohs (bpdu->bridge_id.prio);\
    bpdu->message_age    = ntohs (bpdu->message_age);\
    bpdu->max_age        = ntohs (bpdu->max_age);\
    bpdu->hello_time     = ntohs (bpdu->hello_time);\
    bpdu->fwd_delay      = ntohs (bpdu->fwd_delay);\
} while (0)

/*-------------------------- IGMP protocol data -----------------------------*/
#define IGMP_QUERY         0x11
#define IGMP_MEMBERSHIP_V1 0x12
#define IGMP_MEMBERSHIP_V2 0x16
#define IGMP_LEAVE         0x17
#define IGMP_MEMBERSHIP_V3 0x22

struct proto_igmp
{
    uint8_t  type;        /* IGMP message type */
    uint8_t  resp_time;   /* Response time     */
    uint16_t checksum;
    uint32_t ip_addr;     /* IP group address  */
};

#define proto_igmp_n2h(igmp) do \
{\
    igmp->checksum = ntohs (igmp->checksum);\
    igmp->ip_addr  = ntohl (igmp->ip_addr);\
} while (0)

/*-------------------------- OSPF protocol data -----------------------------*/
struct proto_ospf
{
    uint8_t   version;
    uint8_t   type;         /* OSPF type */
    uint16_t  pkt_length;
    uint32_t  router_id;
    uint32_t  area_id;
    uint16_t  checksum;
    uint16_t  auth_type;
    uint32_t  authentication1;
    uint32_t  authentication2;
};

struct proto_ospf_lsa
{
    uint16_t  ls_age;
    uint8_t   options;
    uint8_t   ls_type;
    uint32_t  link_state_id;
    uint32_t  advert_router;
    uint32_t  seq_num;
    uint16_t  chksum;
    uint16_t  length;
};

struct proto_ospf_hello
{
    uint32_t  network_mask;
    uint16_t  hello_interval;
    uint8_t   options;
    uint8_t   router_prio;
    uint32_t  router_dead_interval;
    uint32_t  designated_router;
    uint32_t  backup_router;
    /*following neighbor 1..n */
};

/*-------------------------- PIM protocol data ------------------------------*/
struct proto_pim
{
    uint8_t  version_type;
    uint8_t  reserved;
    uint16_t checksum;
};

/*-------------------------- VRRP protocol data -----------------------------*/
struct proto_vrrp
{
    uint8_t  version_type;
    uint8_t  vrid;
    uint8_t  priority;
    uint8_t  count_ip;
    uint8_t  auth_type;
    uint8_t  advert_interval;
    uint16_t checksum;
};

/*-------------------------- NTP protocol data -----------------------------*/
struct proto_ntp
{
    uint8_t   flags;
    uint8_t   stratum;
    uint8_t   poll;
    uint8_t   precision;
    uint32_t  root_delay;
    uint32_t  root_dispersion;
    uint8_t   reference_id[4];
    uint32_t  ref_timestamp[2];
    uint32_t  orig_timestamp[2];
    uint32_t  receive_timestamp[2];
    uint32_t  transmit_timestamp[2];
};

#define PROTO_NTP_TIME_N2H(t) t[0] = ntohl(t[0]); t[1] = ntohl(t[1])

#define proto_ntp_n2h(ntp) do \
{\
    ntp->root_delay      = ntohl (ntp->root_delay);\
    ntp->root_dispersion = ntohl (ntp->root_dispersion);\
    PROTO_NTP_TIME_N2H(ntp->ref_timestamp);\
    PROTO_NTP_TIME_N2H(ntp->orig_timestamp);\
    PROTO_NTP_TIME_N2H(ntp->receive_timestamp);\
    PROTO_NTP_TIME_N2H(ntp->transmit_timestamp);\
} while (0)

/*-------------------------- ARP protocol data ------------------------------*/
#define ARP_HW_TYPE_ETHERNET   ((uint16_t) 1)
#define ARP_PROTO_TYPE_IP      ((uint16_t) 0x0800)
#define ARP_HLEN_ETHERNET      ((uint8_t)  6)     /*ethernet address length*/
#define ARP_PLEN_IP            ((uint8_t)  4)     /*IP address length      */

#define ARP_OPER_ARP_REQ       1
#define ARP_OPER_ARP_RESP      2
#define ARP_OPER_RARP_REQ      3
#define ARP_OPER_RARP_RESP     4

#define ARP_MESSAGE_LENGTH     28

/*NOTE: only part of the data can be used in a structure because
        alignment to 32 bytes partially*/
struct proto_arp
{
    uint16_t  hw_typ;          /*hardware type*/
    uint16_t  proto_typ;       /*protocol type*/
    uint8_t   hlen;            /*length of hardware address*/
    uint8_t   plen; 	       /*length of high-layer protocol address*/
    uint16_t  oper;
};

/*-------------------------- ICMP protocol data -----------------------------*/

#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_UNREACH           3
#define ICMP_TYPE_QUENCH            4
#define ICMP_TYPE_REDIR             5
#define ICMP_TYPE_ECHO_REQ          8
#define ICMP_TYPE_RT_DISCOVER       9
#define ICMP_TYPE_RT_SOLICIT       10
#define ICMP_TYPE_TIME_EXCEED      11
#define ICMP_TYPE_PARAM_PROBLEM    12
#define ICMP_TYPE_TIMESTAMP_REQ    13
#define ICMP_TYPE_TIMESTAMP_REPLY  14
#define ICMP_TYPE_INFO_REQ         15
#define ICMP_TYPE_INFO_REPLY       16
#define ICMP_TYPE_SUBNET_REQ       17
#define ICMP_TYPE_SUBNET_REPLY     18

#define ICMP6_TYPE_TOO_BIG          3
#define ICMP6_TYPE_ECHO_REQ       128
#define ICMP6_TYPE_ECHO_REPLY     129
#define ICMP6_TYPE_MCAST_QUERY    130
#define ICMP6_TYPE_MCAST_REPORT   131
#define ICMP6_TYPE_MCAST_DONE     132
#define ICMP6_TYPE_RT_SOLICIT     133
#define ICMP6_TYPE_RT_ADVERT      134
#define ICMP6_TYPE_NEIGHB_SOLICIT 135
#define ICMP6_TYPE_NEIGHB_ADVERT  136
#define ICMP6_TYPE_REDIR          137

struct proto_icmp
{
    uint8_t   type;        /* ICMP message type */
    uint8_t   code;
    uint16_t  checksum;
    uint8_t   data[4];
};

/* Note: more optional data may follow after the ICMP header*/

#define proto_icmp_n2h(icmp) do \
{\
    icmp->checksum = ntohs (icmp->checksum);\
} while (0)

/*-------------------------- BOOTP protocol data ---------------------------*/

#define BOOTP_OPER_REQ     1
#define BOOTP_OPER_RESP    2

#define BOOTP_HTYPE_ETHER  1
#define BOOTP_HLEN_MAC     6

struct proto_bootp
{
    uint8_t   operation;
    uint8_t   htype;
    uint8_t   hlen;
    uint8_t   hops;
    uint32_t  xid;
    uint16_t  secs;
    uint16_t  flags;
    uint32_t  ciaddr;
    uint32_t  yiaddr;
    uint32_t  siaddr;
    uint32_t  giaddr;
    uint8_t   chaddr[16];
    uint8_t   sname[64];  /*optional*/
    uint8_t   file[128];  /*optional*/
};

/*-------------------------- RIP protocol data -----------------------------*/

#define RIP_CMD_REQ     1
#define RIP_CMD_RESP    2

struct proto_rip_hd
{
    uint8_t   command;
    uint8_t   version;
    uint16_t  res;
};

struct proto_rip_entry
{
    uint16_t  afi;
    uint16_t  res;
    uint32_t  ipaddr;
    uint32_t  netmask;
    uint32_t  nexthop;
    uint32_t  metric;
};

/*------------------------- global function declarations ------------------*/

/* functions for dumping message */
void dump_packet (const uint8_t *p, uint32_t n);
void dump_test_packet (const uint8_t *p, uint32_t n, int is_testdata);
void dump_hex (const uint8_t *p, uint32_t n);
const char* get_icmp_type_text(uint8_t type);
const char* get_icmp6_type_text(uint8_t type);
const char* get_udp_port_text(uint16_t port);

uint16_t IP_chksum(const void* buf, int size);
uint32_t IP_chksum_add_sum(const void* buf, int size, uint32_t sum);
uint16_t IP_chksum_calc_sum(uint32_t sum);

#endif
