/****************************************************************************
 *  Traffic Analyzer
 *---------------------------------------------------------------------------
 *  Capture and analyze packets received on specified interface.
 *
 *  The results are sent all <timeout> seconds as a JSON string on STDOUT
 *  or socket.
 *
 *  ## Copyright ## T.B.D.
 *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <pcap.h>

#include <jansson.h>
#include <glib.h>

#include "netsock.h"

#define UNUSED(x) (void)x

#define DEF_INTERVAL_MSEC  1000

/* filter definitions */

#define MAX_FILTER  8

typedef struct {
    gchar*             jsonName;   /* name for filter (command argument) */
    gchar*             pcapExpr;   /* PCAP expression (command argument) */
    pcap_t*            pcap;       /* (internal for PCAP)                */
    struct bpf_program bpf;        /* (internal for PCAP                 */
    gint               counter;    /* received bytes                    */
} t_pcap_filter;

static t_pcap_filter* pcapFilter[MAX_FILTER];
static gint           pcapFilterCount = 0;

/*---------------------------------------------------------------------------
 *  Utilities
 *-------------------------------------------------------------------------*/

static void print_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf (stderr, "error: ");
    vfprintf (stderr, fmt, args);
    fprintf (stderr, "\n");
    va_end(args);
}

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

/*---------------------------------------------------------------------------
 *  Handle Filter
 *-------------------------------------------------------------------------*/

static void init_filter (const gchar* jsonName, const gchar* pcapExprString)
{
    t_pcap_filter* pFilter;

    /* allocate new filter entry */
    if ((pcapFilterCount + 1) >= MAX_FILTER) {
        print_error("Too much filters specified (max=%d)", MAX_FILTER);
        exit (EINVAL);
    }
    pFilter = malloc (sizeof(*pFilter));
    if (pFilter == NULL) {
        print_error ("malloc failed");
        exit (ENOMEM);
    }
    memset (pFilter, 0, sizeof(*pFilter));

    /* add JSON-Name and PCAP expression */
    pFilter->jsonName = g_strdup (jsonName);
    if (pFilter->jsonName == NULL) {
        print_error ("malloc failed");
        exit (ENOMEM);
    }

    if (pcapExprString != NULL) {
        pFilter->pcapExpr = g_strdup (pcapExprString);
        if (pFilter->pcapExpr == NULL) {
            print_error ("malloc failed");
            exit (ENOMEM);
        }
    }

    /* add new filter in filter list */
    pcapFilter[pcapFilterCount++] = pFilter;
}

/*---------------------------------------------------------------------------
 *  Write Statistics
 *-------------------------------------------------------------------------*/
/*
 * The statistics are coded in JSON format:
 *   {
 *     "type"   : "bandwidth-data" ,
 *     "object" : {
 *         "timestamp-start" : "<iso-time>" ,
 *         "timestamp-end" : "<iso-time>" ,
 *         "data" : [
 *            {
 *              "filter-name" : "<filterName1> ,
 *              "filter-expression : "<filterExpr1>,
 *              "byte-count" : <value-bytes1>
 *              "bandwidth" : <value-bandwidth1>
 *            },
 *            ...,
 *            {
 *              "filter-name" : "<filterNameN> ,
 *              "filter-expression : "<filterExprN>,
 *              "byte-count" : <value-bytesN>
 *              "bandwidth" : <value-bandwidthN>
 *            }
 *         ]
 *      }
 *   }
 *
 *   Example ISO Time: "2008-09-03T20:56:35.450686Z"
 *   FilterExpr if none filter is set: "all"
 */

#define JSON_OBJ_NAME_TYPE            "type"
#define JSON_OBJ_NAME_OBJ             "object"
#define JSON_OBJ_NAME_TIME_START      "timestamp-start"
#define JSON_OBJ_NAME_TIME_END        "timestamp-end"
#define JSON_OBJ_NAME_DATA            "data"
#define JSON_OBJ_NAME_FILTER_NAME     "filter-name"
#define JSON_OBJ_NAME_FILTER_EXPR     "filter-expression"
#define JSON_OBJ_NAME_FILTER_COUNT    "byte-count"
#define JSON_OBJ_NAME_FILTER_BW       "bandwidth"

#define JSON_OBJ_VAL_TYPE             "bandwidth-data"

#define JSON_OBJ_VAL_FILTER_EXPR_NONE "all"

/* Utilities */

static void set_json_data_timestamp (json_t* pJsonObj, GTimeVal* pTime,
                                     const gchar* pTimeObjName)
{
    json_t* pJsonVal;
    gchar*  pIsoTime;

    pIsoTime = g_time_val_to_iso8601 (pTime);
    pJsonVal = json_string (pIsoTime);
    json_object_set_new (pJsonObj, pTimeObjName, pJsonVal);
    g_free(pIsoTime);
}

static void set_json_filter_result (json_t* pJsonArray, t_pcap_filter* pFilter,
                                    guint32 intervalMsec)
{
    json_t *pJsonObj, *pJsonVal;
    double counterMbit;

    /* generate one filter object */
    pJsonObj = json_object();

    /* - filter-name */
    pJsonVal = json_string (pFilter->jsonName);
    json_object_set_new (pJsonObj, JSON_OBJ_NAME_FILTER_NAME, pJsonVal);

    /* - filter-expression */
    pJsonVal = json_string (pFilter->pcapExpr);
    json_object_set_new (pJsonObj, JSON_OBJ_NAME_FILTER_EXPR, pJsonVal);

    /* - byte-counter */
    pJsonVal = json_integer (pFilter->counter);
    json_object_set_new (pJsonObj, JSON_OBJ_NAME_FILTER_COUNT, pJsonVal);

    /* - bandwidth */
    counterMbit = calc_mbit_per_sec (pFilter->counter, intervalMsec);
    pJsonVal = json_real (counterMbit);
    json_object_set_new (pJsonObj, JSON_OBJ_NAME_FILTER_BW, pJsonVal);

    /* add filter object to array */
    json_array_append (pJsonArray, pJsonObj);

    json_decref (pJsonObj);

    /* reset the read counter */
    pFilter->counter = 0;
}

/* write statistics in JSON format */

static char* generate_statistics (guint32 intervalMsec,
                                  GTimeVal* pTimeStart, GTimeVal* pTimeEnd)
{
    json_t *pJson, *pJsonObj, *pJsonVal, *pJsonArray;
    char*  pJsonString;
    gint   idx;

    /* generate fixed objects */
    /* - basic object containing all other objects */
    pJson = json_object();

    /* - type */
    pJsonVal = json_string (JSON_OBJ_VAL_TYPE);
    json_object_set_new (pJson, JSON_OBJ_NAME_TYPE, pJsonVal);

    /* - object */
    pJsonObj = json_object();
    json_object_set_new (pJson, JSON_OBJ_NAME_OBJ, pJsonObj);

    /* - timestamp-start / timestamp-end */
    set_json_data_timestamp (pJsonObj, pTimeStart, JSON_OBJ_NAME_TIME_START);
    set_json_data_timestamp (pJsonObj, pTimeEnd, JSON_OBJ_NAME_TIME_END);

    /* - data */
    pJsonArray  = json_array ();
    json_object_set_new (pJsonObj, JSON_OBJ_NAME_DATA, pJsonArray);

    /* generate variable filter objects */
    for (idx = 0; idx < pcapFilterCount; idx++) {
        /* generate one filter object */
        set_json_filter_result (pJsonArray, pcapFilter[idx], intervalMsec);
    }

    /* Serialize JSON object */
    pJsonString = json_dumps(pJson, JSON_COMPACT);
    if (pJsonString == NULL) {
        print_error ("Encoding JSON object failed");
        exit (EPERM);
    }

    json_decref (pJsonArray);
    json_decref (pJsonObj);
    json_decref (pJson);

    return pJsonString;
}

/*---------------------------------------------------------------------------
 *  PCAP Handling
 *-------------------------------------------------------------------------*/

static void pcap_callback(u_char *userContext, const struct pcap_pkthdr *hdr,
                          const u_char *packetData)
{
    guint32* pCounter = (guint32*) userContext;

    UNUSED(packetData);

    if (hdr->caplen != hdr->len) {
        print_error ("got only part of packet");
    }
    (*pCounter) += hdr->caplen;
}

static pcap_t* netreceive_pcap_open (char* pDev, guint32 intervalMsec)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (pDev == NULL) {
        pDev = pcap_lookupdev(errbuf);
        if (pDev == NULL) {
            print_error ("Couldn't find default device: %s", errbuf);
            return NULL;
        }
    }
    int readTimeMsec = intervalMsec / 4;
    handle = pcap_open_live (pDev, BUFSIZ, 1, readTimeMsec, errbuf);
    if (handle == NULL) {
        print_error ("Couldn't open device %s: %s", pDev, errbuf);
        return NULL;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        print_error ("Device %s doesn't provide Ethernet headers", pDev);
        return NULL;
    }

    if (pcap_setnonblock(handle, 1, errbuf)) {
        print_error ("Couldn't set non-blocking %s: %s", pDev, errbuf);
        return NULL;
    }

    /* handle only received packets */
    if (pcap_setdirection(handle, PCAP_D_IN)) {
        print_error("Couldn't set direction for device %s: %s", pDev, errbuf);
        return NULL;
    }

    return handle;
}

/*---------------------------------------------------------------------------
 *  run traffic analyzing
 *-------------------------------------------------------------------------*/

static int netreceive_run (char* pDev, guint32 intervalMsec,
                           const char* socketName)
{
    int rc;
    int idx;
    int fdSock = (-1);
    pcap_t* pcap;
    GTimeVal timeStart, timeCur;
    guint32 elapsedTime;
    gchar* pJsonString;

    signal(SIGPIPE, SIG_IGN);

    /* open socket for writing result */
    if (socketName != NULL) {
        fdSock = open_netreceive_socket(socketName);
        if (fdSock < 0) {
            print_error ("Couldn't open socket to send statistics");
            return EIO;
        }
    }

    /* now initialize pcap filter for all specified filters */
    /* set default filter ("all") if no filter specified */
    if (pcapFilterCount == 0) {
        init_filter (JSON_OBJ_VAL_FILTER_EXPR_NONE, NULL);
    }

    /* generate for each requested filter rule a separate pcap instance */
    for (idx = 0; idx < pcapFilterCount; idx++) {
        pcap = netreceive_pcap_open(pDev, intervalMsec);
        if (pcap == NULL) {
            return ENOENT;
        }
        pcapFilter[idx]->pcap = pcap;

        /* do not set a filter if no filter requested */
        if (pcapFilter[idx]->pcapExpr == NULL) {
            continue;
        }

        rc = pcap_compile (pcap, &pcapFilter[idx]->bpf,
                           pcapFilter[idx]->pcapExpr,
                           1, PCAP_NETMASK_UNKNOWN);
        if (rc) {
            print_error ("invalid PCAP expression '%s'",
                         pcapFilter[idx]->pcapExpr);
            return EINVAL;
        }

        rc = pcap_setfilter(pcap, &pcapFilter[idx]->bpf);
        if (rc) {
            print_error ("Cannot set PCAP filter '%s'",
                         pcapFilter[idx]->pcapExpr);
            return EACCES;
        }
    }

    /* run pcap filter and print data after specified interval */
    g_get_current_time(&timeStart);
    while (1) {

        for (idx = 0; idx < pcapFilterCount; idx++) {
            (void) pcap_dispatch (pcapFilter[idx]->pcap, 0, pcap_callback,
                                  (u_char*) &pcapFilter[idx]->counter);
        }

        g_get_current_time(&timeCur);

        /* elapsedTime in milliseconds */
        elapsedTime  = (timeCur.tv_sec  - timeStart.tv_sec ) * 1000.0;
        elapsedTime += (timeCur.tv_usec - timeStart.tv_usec) / 1000.0;

        if (elapsedTime >= intervalMsec) {
            pJsonString = generate_statistics (elapsedTime, &timeStart,
                                               &timeCur);
            /* the function above resets the counters if read */

            if (socketName == NULL) {
                printf("%s\n", pJsonString);
            } else {
                (void) write_netreceive_socket (fdSock, pJsonString);
            }
            free (pJsonString);

            /* set new start time */
            g_get_current_time(&timeStart);
        }

        usleep(20);
    }

    /* close all pcap instances */
    for (idx = 0; idx < pcapFilterCount; idx++) {
        pcap_close(pcapFilter[idx]->pcap);
    }

    return 0;
}

/*---------------------------------------------------------------------------
 *  read configuration file
 *-------------------------------------------------------------------------*/

static void read_config_file (gchar* pFileName)
{
    GKeyFile* pKeyFile;
    GError*   error;
    gchar**   groups;
    gchar**   keys;
    gchar*    value;
    gsize     numGroups, numKeys;
    gint      iGrp, iKey;
    gboolean  rv;

    pKeyFile = g_key_file_new();
    rv = g_key_file_load_from_file (pKeyFile, pFileName, G_KEY_FILE_NONE,
                                    &error);
    if (rv == FALSE) {
        if (error->code == G_FILE_ERROR_NOENT) {
            print_error ("configuration file '%s' not found", pFileName);
        } else {
            print_error ("configuration file data incorrect");
        }
        exit (EINVAL);
    }

    groups = g_key_file_get_groups (pKeyFile, &numGroups);
    if ((groups == 0) || (numGroups == 0)) {
        print_error ("configuration file: no groups found.");
        return;
    }
    for (iGrp = 0; iGrp < (gint) numGroups; iGrp++) {
        keys = g_key_file_get_keys (pKeyFile, groups[iGrp], &numKeys, &error);
        if ((keys == NULL) || (numKeys == 0)) {
            print_error ("configuration file: no keys for group '%s' found.",
                         groups[iGrp]);
            continue;
        }
        for (iKey = 0; iKey < (gint) numKeys; iKey++) {
            value = g_key_file_get_string (pKeyFile, groups[iGrp],
                                           keys[iKey], &error);
            if (value == NULL) {
                print_error ("configuration file: no value for group '%s'"
                             " and key '%s' found.",
                             groups[iGrp], keys[iKey]);
                continue;
            }

            /* special handling for no filter */
            if (strcmp(value, "all") == 0) {
                g_free (value);
                value = NULL;
            }

            if (strcmp (keys[iKey], JSON_OBJ_NAME_FILTER_EXPR) == 0) {
                init_filter (groups[iGrp], value);
            }
            else {
                print_error ("configuration file: unknown key '%s'",
                             keys[iKey]);
            }
            g_free(value);
        }
        g_strfreev (keys);
    }
    g_strfreev (groups);
    g_key_file_free (pKeyFile);
}

/*---------------------------------------------------------------------------
 *  M A I N  (handling arguments)
 *-------------------------------------------------------------------------*/

static gchar*  o_configFile   = NULL;
static guint32 o_intervalMsec = DEF_INTERVAL_MSEC;
static gchar*  o_socketName   = NULL;

static gboolean o_callback_filter (const gchar *key, const gchar *value,
                                   gpointer user_data, GError *error)
{
    /* the value for the filter option is found in 'value'. All other
     * parameters are not used.
     */
    UNUSED(key);
    UNUSED(user_data);
    UNUSED(error);

    /* The format of the filter option is: <name>=<pcap-filter-string> */
    gchar** filterData;
    filterData = g_strsplit(value, ":", 2);
    if (g_strv_length(filterData) != 2) {
        return FALSE;
    }

    init_filter (filterData[0], filterData[1]);

    g_strfreev(filterData);
    return TRUE;
}

static GOptionEntry optionList[] =
{
    { "config", 'c', 0, G_OPTION_ARG_STRING, &o_configFile,
      "Read the filter from specified configuration file.",
      "file-name"                                                          },

    { "filter", 'f', 0, G_OPTION_ARG_CALLBACK, o_callback_filter,
      "Set filter as <name>:<pcap-filter>. Multiply filter allowed.",
      "filter"                                                             },

    { "interval", 'i', 0, G_OPTION_ARG_INT, &o_intervalMsec,
      "Interval for counting in milliseconds.",
      "interval"                                                           },

    { "socket", 's', 0, G_OPTION_ARG_STRING, &o_socketName,
      "Write result to a socket with specified name instead of stdout",
      "name"                                                               },

    { NULL, '\0', 0, 0, NULL, NULL, NULL }
};

int main(int argc, char** argv)
{
    GOptionContext* optionContext;
    GError*         error = NULL;
    gchar*          dev = NULL;

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

    if (o_configFile != NULL) {
        read_config_file (o_configFile);
    }

    return netreceive_run (dev, o_intervalMsec, o_socketName);
}

/*---- end-of-file ----*/
