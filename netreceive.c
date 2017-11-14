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
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <pcap.h>

#include <jansson.h>
#include <glib.h>

#include "netdata.h"
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

typedef struct {
    gint     protoTyp;
    guint32  value;
} t_filter;

typedef struct {
    const gchar*  jsonName;
    t_filter*     filter;
} t_stat;

/* specify default filters for TSN, video, bulk */

static t_filter filter_tsn[] = {
    { PROTO_ETH_TYPE,   0x0808 },
    { 0,                0      }
};
static t_filter filter_video[] = {
    { PROTO_UDP_DPORT,  1234   },
    { 0,                0      }
};
static t_filter filter_bulk[] = {
    { PROTO_ETH_TYPE,   0x080a },
    { 0,                0      }
};

/* specify traffic classes */

static t_stat statInfoList[] =
{
    { "total", NULL         },  /* TYP_TOTAL */
    { "tsn",   filter_tsn   },  /* TYP_TSN   */
    { "video", filter_video },  /* TYP_VIDEO */
    { "bulk",  filter_bulk  },  /* TYP_BULK  */

    { NULL,    0            }
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
                          protodata_t* pProto)
{
    int       i;
    t_filter* pFilter;

    for (i = 0; (i < TYP_LAST) && (statInfoList[i].jsonName != NULL); i++) {

        if (statInfoList[i].filter == NULL) {
            pCounter[i] += packetLength;
            continue;
        }

        pFilter = statInfoList[i].filter;
        while (pFilter->protoTyp > 0) {
            switch (pFilter->protoTyp) {
            case PROTO_ETH_TYPE:
                if ((pProto->exist & PROTO_ETH_TYPE) &&
                    ((guint32) pProto->ethType == pFilter->value)) {
                    pCounter[i] += packetLength;
                }
                break;
            case PROTO_UDP_DPORT:
                if ((pProto->exist & PROTO_UDP_DPORT) &&
                    ((guint32) pProto->udpDestPort == pFilter->value)) {
                    pCounter[i] += packetLength;
                }
                break;
            default:
                fprintf(stderr, "Unknown filter type '%d'", pFilter->protoTyp);
                break;
            }
            pFilter++;
        }
    }
}

/*---------------------------------------------------------------------------
 *  PCAP Handling
 *-------------------------------------------------------------------------*/

static void pcap_callback(u_char *userContext, const struct pcap_pkthdr *hdr,
                          const u_char *packetData)
{
    guint32*    pCounter = (guint32*) userContext;
    protodata_t proto;

    if (hdr->caplen != hdr->len) {
        fprintf(stderr, "got only part of packet");
    }
    analyze_eth_packet (&proto, packetData, hdr->caplen);
    check_filter (pCounter, hdr->caplen, &proto);
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

	usleep(20);
    }

    pcap_close(handle);

    return 0;
}

/*---------------------------------------------------------------------------
 *  M A I N
 *-------------------------------------------------------------------------*/

static guint32 o_intervalMsec = DEF_INTERVAL_MSEC;
static gchar*  o_socketName   = DEF_SOCKET_NAME;

static GOptionEntry optionList[] =
{
    { "socket", 's', 0, G_OPTION_ARG_STRING, &o_socketName,
      "Socket name for writing result to", "name"                        },
    { "interval", 'i', 0, G_OPTION_ARG_INT, &o_intervalMsec,
      "Interval for counting in msec", "interval"                        },

    /* debug */
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
