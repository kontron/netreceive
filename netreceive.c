/****************************************************************************
 *  Traffic Analyzer
 *
 *  Capture and analyze packets received on specified interface.
 *
 *  The results are sent all <timeout> seconds as a JSON string on a socket.
 *  The unit of the counters is MBit/second.
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

static gint         o_dbg_dump       = 0;
static gint         o_dbg_bytes      = 0;
static const gchar* o_dbg_fix_values = NULL;

enum {
    TYP_TOTAL = 0, TYP_TSN, TYP_VIDEO, TYP_BULK,
    TYP_LAST
};

#define FILTER_NONE       0
#define FILTER_ETH_TYP    1
#define FILTER_UDP_DPORT  2
#define FILTER_UNDEF      9

typedef struct {
    const gchar* jsonName;
    gint         filterTyp;
    guint32      filterValue;
} t_stat;

static t_stat statInfoList[] =
{
    { "total", FILTER_NONE,           0 },   /* TYP_TOTAL */
    { "tsn",   FILTER_ETH_TYP,   0x0808 },   /* TYP_TSN   */
    { "video", FILTER_UDP_DPORT,   1234 },   /* TYP_VIDEO */
    { "bulk",  FILTER_UNDEF,          0 },   /* TYP_BULK  */

    { NULL,    FILTER_UNDEF,          0 }
};

/*---------------------------------------------------------------------------
 *  Write Statistics
 *-------------------------------------------------------------------------*/

static double calc_mbit_per_sec (guint32 countBytes, guint32 intervalMsec)
{
    double countMbit;

    /* calculate bits */
    countMbit = (double)(countBytes * 8);
    /* calculate bits per second */
    countMbit *= ((double) 1000 / (double) intervalMsec);
    /* calculate Mbit per second */
    if (countMbit > 0) {
        countMbit /= (double)(1024 * 1024);
    }
    return countMbit;
}

static void write_statistics (int fdSock, guint32 intervalMsec,
                                          guint32* pCounter)
{
    json_t* pJson;
    char*   pJsonString;
    double  counterMbit[TYP_LAST];
    gint    i;

    /* Calculate Mbit/sec */
    for (i = 0; i < TYP_LAST; i++) {
         counterMbit[i] = calc_mbit_per_sec(pCounter[i],intervalMsec);
    }

    /* for debug: set fixed values if no traffic generated */
    if (o_dbg_fix_values != NULL) {
        gchar** fixValueList;
        double fixValue;
        fixValueList = g_strsplit_set(o_dbg_fix_values, "/", -1);
        for (i = 0; i < TYP_LAST; i++) {
            if (fixValueList[i] == NULL) {
                break;
            }
            fixValue = atof(fixValueList[i]);
            if (fixValue > 0) {
                counterMbit[i] = fixValue;
            }
        }
        g_strfreev(fixValueList);
    }

    /* Generate JSON object */
    if (o_dbg_bytes) {
        /* for debugging */
        pJson = json_pack ("{sisisisi}",
                  statInfoList[TYP_TOTAL].jsonName, pCounter[TYP_TOTAL],
                  statInfoList[TYP_TSN].jsonName,   pCounter[TYP_TSN],
                  statInfoList[TYP_VIDEO].jsonName, pCounter[TYP_VIDEO],
                  statInfoList[TYP_BULK].jsonName,  pCounter[TYP_BULK]
                  );
    }
    else {
        pJson = json_pack ("{sfsfsfsf}",
                  statInfoList[TYP_TOTAL].jsonName, counterMbit[TYP_TOTAL],
                  statInfoList[TYP_TSN].jsonName,   counterMbit[TYP_TSN],
                  statInfoList[TYP_VIDEO].jsonName, counterMbit[TYP_VIDEO],
                  statInfoList[TYP_BULK].jsonName,  counterMbit[TYP_BULK]
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

    if (o_dbg_dump) {
        printf("%s\n", pJsonString);
    }

    /* Write JSON information to application socket */
    (void) write_netreceive_socket (fdSock, pJsonString);

    free(pJsonString);
}

/*---------------------------------------------------------------------------
 *  Filter
 *-------------------------------------------------------------------------*/

static void check_filter (guint32* pCounter, guint32 packetLength,
                          guint16 ethType, guint16 udpDestPort)
{
    int i;
    for (i = 0; (i < TYP_LAST) && (statInfoList[i].jsonName != NULL); i++) {
        switch (statInfoList[i].filterTyp) {
        case FILTER_NONE:
            pCounter[i] += packetLength;
            break;
        case FILTER_ETH_TYP:
            if ((guint32) ethType == statInfoList[i].filterValue) {
                pCounter[i] += packetLength;
            }
            break;
        case FILTER_UDP_DPORT:
            if ((guint32) udpDestPort == statInfoList[i].filterValue) {
                pCounter[i] += packetLength;
            }
            break;
        default:
            /* do not count */
            break;
        }
    }
}

/*---------------------------------------------------------------------------
 *  Analyze Packet
 *-------------------------------------------------------------------------*/

static gboolean is_vlan_ether_type (guint16 eth_type)
{
    return (eth_type == TPID_802_1Q_ETHERNET
            || eth_type == TPID_802_1AD_ETHERNET);
}

static void analyze_packet(guint32* pCounter, const guint8 *packet,
                           guint32 packetLength)
{
    struct mcl_ether* pEth;
    guint16           ethType;
    const guint8*     pp  = packet;
    guint32           len = packetLength;
    guint16           udpDestPort = 0;

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

//    pCounter[TYP_TOTAL] += packetLength;

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
                udpDestPort = ntohs(pUdp->dport);
                //pp   += sizeof(struct mcl_udphdr);
                //len -= sizeof(struct mcl_udphdr);
            }
        }
    }

    check_filter (pCounter, packetLength, ethType, udpDestPort);
}

/*---------------------------------------------------------------------------
 *  PCAP Handling
 *-------------------------------------------------------------------------*/

static void pcap_callback(u_char *userContext, const struct pcap_pkthdr *hdr,
                          const u_char *packetData)
{
    guint32* pCounter = (guint32*) userContext;

    if (hdr->caplen != hdr->len) {
        fprintf(stderr, "got only part of packet");
    }
    analyze_packet (pCounter, packetData, hdr->caplen);
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
    guint32 counter[TYP_LAST];

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
    memset(counter, 0, sizeof(counter));
    while (1) {
        (void) pcap_dispatch(handle, 0, pcap_callback, (u_char*) counter);

        gettimeofday(&timeCur, NULL);

        /* elapsedTime in milliseconds */
        elapsedTime  = (timeCur.tv_sec - timeStart.tv_sec) * 1000.0;
        elapsedTime += (timeCur.tv_usec - timeStart.tv_usec) / 1000.0;

        if (elapsedTime >= intervalMsec) {
            write_statistics (fdSock, intervalMsec, counter);

            memset(counter, 0, sizeof(counter));
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

    /* filter */
    { "video", 'v', 0, G_OPTION_ARG_INT,
      &(statInfoList[TYP_VIDEO].filterValue),
      "For video counter filter by UDP destination port", "port"         },

    /*debug*/
    { "dump", 'd', 0, G_OPTION_ARG_NONE, &o_dbg_dump,
      "Dump packet counters", NULL                                       },
    { "dbgbytes", 'b', 0, G_OPTION_ARG_NONE, &o_dbg_bytes,
      "Send counted bytes instead of Mbit/sec (for debug)", NULL         },
    { "dbgval", 'x', 0, G_OPTION_ARG_STRING, &o_dbg_fix_values,
      "Set fixed values in Mbit/sec for total/tsn/video/bulk"
      " (0 .. not fix)", "values"                                        },

    { NULL, '\0', 0, 0, NULL, NULL, NULL }
};

int main(int argc, char** argv)
{
    GOptionContext* optionContext;
    GError*         error = NULL;
    char*           dev = NULL;

    optionContext = g_option_context_new ("[ <interface> ]");
    g_option_context_set_summary(optionContext,
         "Traffic Analyzer Tool - counts received packets on a interface");
    g_option_context_add_main_entries (optionContext, optionList, NULL);
    if (!g_option_context_parse (optionContext, &argc, &argv, &error)) {
        g_print ("Option parsing failed: %s\n", error->message);
        exit (EINVAL);
    }
    free(optionContext);

    if (argc > 0) {
        dev = argv[1];
    }

    return netreceive_run (dev, o_intervalMsec, o_socketName);
}

/*---- end-of-file ----*/
