/****************************************************************************
 *  Traffic Analyzer:
 *
 *  Capture and analyze packets received on specified interface.
 *
 *  The results are sent all <timeout> seconds as a string on a socket.
 *  The format of the string is:
 *     "<total> Mbit/sec"
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>

#include <jansson.h>
#include <glib.h>

#include "datainfo.h"
#include "netsock.h"

#define UNUSED(x) (void)x

#define DEF_INTERVAL_MSEC  1000
#define DEF_SOCKET_NAME    "/tmp/traffic.socket"

static gint o_is_dump_stats   = 0;
static gint o_is_result_bytes = 0;
static gint o_udp_dport       = 0;

typedef struct {
    int  totalBytes;
    int  videoBytes;
} t_stat;

/*---------------------------------------------------------------------------
 *  Write Statistics
 *-------------------------------------------------------------------------*/

#define CALC_MBIT_SEC(v,i)\
                  ((double)(v * 8)/(double)(1024 * 1024) / (double)(i / 1000))

static void write_statistics (int fdSock, guint32 intervalMsec, t_stat* pStat)
{
    json_t* pJson;
    char*   pJsonString;

    /* Generate JSON object */
    if (o_is_result_bytes) {
        pJson = json_pack ("{sisi}",
                           "total", pStat->totalBytes,
                           "video", pStat->videoBytes
                          );
    }
    else {
        pJson = json_pack ("{sfsf}",
                           "total",
                           CALC_MBIT_SEC(pStat->totalBytes,intervalMsec),
                           "video",
                           CALC_MBIT_SEC(pStat->videoBytes,intervalMsec)
                          );
    }
    if (pJson == NULL) {
        fprintf(stderr, "Building JSON object failed\n");
        exit (EPERM);
    }

    /* Serialize JSON object */
    pJsonString = json_dumps(pJson, JSON_COMPACT);
    if (pJsonString == NULL) {
        fprintf(stderr, "Encoding JSON object failed\n");
        exit (EPERM);
    }

    if (o_is_dump_stats) {
        printf("%s\n", pJsonString);
    }

    /* Write JSON information to application socket */
    (void) write_netreceive_socket (fdSock, pJsonString);

    free(pJsonString);
}

/*---------------------------------------------------------------------------
 *  Analyze Packet
 *-------------------------------------------------------------------------*/

static gboolean is_vlan_ether_type (guint16 eth_type)
{
    return (eth_type == TPID_802_1Q_ETHERNET
            || eth_type == TPID_802_1AD_ETHERNET);
}

static void analyze_packet(t_stat* pStat, const guint8 *packet,
                           guint32 packetLength)
{
    struct mcl_ether* pEth;
    guint16           ethType;
    const guint8*     pp  = packet;
    guint32           len = packetLength;

    /*--- Analyze ethernet header ---*/

    /* packets without complete ethernet header are ignored */
    if (len < sizeof (struct mcl_ether)) {
        return;
    }

    pEth    = (struct mcl_ether*) pp;
    ethType = ntohs(pEth->ether_type);

    /* check for VLAN tag */
    if (is_vlan_ether_type(ethType)) {
        struct mcl_vlan* pEthVlan;
        //guint8           vlanPrio;

        pEthVlan = (struct mcl_vlan*) pp;
        ethType  = ntohs(pEthVlan->ether_type);
        //vlanPrio = ((((guint8*) &pEthVlan->tci)[0]) >> 5);

        pp  += sizeof(struct mcl_vlan);
        len -= sizeof(struct mcl_vlan);

        /* double vlan tag */
        if (is_vlan_ether_type(ethType)) {
            pp += 2;
            ethType = ntohs(*((uint16_t*) pp));
            pp += 2;
            len -= 5;
        }
    }
    else {
        pp  += sizeof(struct mcl_ether);
        len -= sizeof(struct mcl_ether);
    }

    pStat->totalBytes += packetLength;

    /*--- Analyze IP header ---*/

    if (ethType == MCL_ETHER_TYPE_IP) {
        struct mcl_iphdr *pIp;
        gint hdrSize;
        //guint16 chksum;

        pIp = (struct mcl_iphdr *) pp;
        if (len < sizeof (struct mcl_iphdr)) {
            return;
        }

        pp  += sizeof(struct mcl_iphdr);
        len -= sizeof(struct mcl_iphdr);

        hdrSize = (int)(pIp->hdrlength_version & 0x0f); /*32-bit words*/

        /* check checksum (length in 16-bit words) */
        // chksum = ip->chksum;
        // ip->chksum = 0;
        // if (IP_chksum(ip, (hdr_size * 2)) != chksum ) {
        //  	printf("IP checksum error\n");
        //	}

        /* IP options */
        int option_len;
        option_len = hdrSize - MCL_IP_HEADERLEN(0);
        pp  += (option_len * 4);
        len -= (option_len * 4);

        /*--- analyze UDP header ---*/

        if (pIp->protocol == MCL_IP_PROTOCOL_UDP) {
            if (len >= sizeof(struct mcl_udphdr)) {
                struct mcl_udphdr* pUdp = (struct mcl_udphdr*) pp;
                if ((o_udp_dport > 0) &&
                    (o_udp_dport == ntohs(pUdp->dport))) {

                    pStat->videoBytes += packetLength;
                }
                //pp   += sizeof(struct mcl_udphdr);
                //len -= sizeof(struct mcl_udphdr);
            }
        }
    }
}

/*---------------------------------------------------------------------------
 *  PCAP Handling
 *-------------------------------------------------------------------------*/

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                          const u_char *bytes)
{
    t_stat* pStat = (t_stat*) user;

    if (hdr->caplen != hdr->len) {
        fprintf(stderr, "got only part of packet");
    }
    analyze_packet (pStat, bytes, hdr->caplen);
}

static pcap_t* netreceive_pcap_open (char* pDev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (pDev == NULL) {
        pDev = pcap_lookupdev(errbuf);
        if (pDev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return NULL;
        }
    }
    printf("Device: %s\n", pDev);

    handle = pcap_open_live(pDev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", pDev, errbuf);
        return NULL;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", pDev);
        return NULL;
    }

    if (pcap_setnonblock(handle, 1, errbuf)) {
        fprintf(stderr, "Couldn't set non-blocking %s: %s\n", pDev, errbuf);
        return NULL;
    }

    /* handle only received packets */
    if (pcap_setdirection(handle, PCAP_D_IN)) {
        fprintf(stderr, "Couldn't set direction for device %s: %s\n", pDev, errbuf);
        return NULL;
    }

    return handle;
}

/*---------------------------------------------------------------------------
 *  run traffic analyzing
 *-------------------------------------------------------------------------*/

int netreceive_run (char* pDev, guint32 intervalMsec, const char* socketName)
{
    pcap_t* handle;
    int fdSock;
    struct timeval timeStart, timeCur;
    guint32 elapsedTime;
    t_stat statistics;

    handle = netreceive_pcap_open(pDev);
    if (handle == NULL) {
        return ENOENT;
    }

    fdSock = open_netreceive_socket(socketName);
    if (fdSock < 0) {
        fprintf(stderr, "Couldn't open socket to send statistics\n");
        return EIO;
    }

    gettimeofday(&timeStart, NULL);
    memset(&statistics, 0, sizeof(statistics));
    while (1) {
        (void) pcap_dispatch(handle, 0, pcap_callback, (u_char*) &statistics);

        gettimeofday(&timeCur, NULL);

        /* elapsedTime in milliseconds */
        elapsedTime  = (timeCur.tv_sec - timeStart.tv_sec) * 1000.0;
        elapsedTime += (timeCur.tv_usec - timeStart.tv_usec) / 1000.0;

        if (elapsedTime >= intervalMsec) {
            write_statistics (fdSock, intervalMsec, &statistics);

            memset(&statistics, 0, sizeof(statistics));
            gettimeofday(&timeStart, NULL);
        }
    }

    pcap_close(handle);

    return 0;
}

/*---------------------------------------------------------------------------
 *  M A I N
 *-------------------------------------------------------------------------*/

static guint32 o_intervalMsec = DEF_INTERVAL_MSEC;
static char*   o_socketName   = DEF_SOCKET_NAME;

static GOptionEntry optionList[] =
{
    { "socket", 's', 0, G_OPTION_ARG_STRING, &o_socketName,
      "Socket name for writing result to", "name"                        },
    { "interval", 'i', 0, G_OPTION_ARG_INT, &o_intervalMsec,
      "Interval for counting in msec", "interval"                        },
    { "dump", 'd', 0, G_OPTION_ARG_NONE, &o_is_dump_stats,
      "Dump packet counters", NULL                                       },
    { "bytes", 'b', 0, G_OPTION_ARG_NONE, &o_is_result_bytes,
      "Send counted bytes instead of Mbit/sec (for debug)", NULL         },

    { "udp", 'u', 0, G_OPTION_ARG_INT, &o_udp_dport,
      "Count packets for specified UDP destination port", "port"         },

    { NULL, '\0', 0, 0, NULL, NULL, NULL }
};

int main(int argc, char** argv)
{
    GOptionContext* optionContext;
    GError*         error = NULL;
    char*           dev = NULL;

    optionContext = g_option_context_new ("Run OPC-UA Server");
    g_option_context_add_main_entries (optionContext, optionList, NULL);
    if (!g_option_context_parse (optionContext, &argc, &argv, &error)) {
        g_print ("Option parsing failed: %s\n", error->message);
        exit (EINVAL);
    }

    if (argc > 0) {
        dev = argv[1];
    }

    return netreceive_run (dev, o_intervalMsec, o_socketName);
}

/*---- end-of-file ----*/
