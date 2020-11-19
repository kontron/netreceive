/******************************************************************************
 *
 * Copyright (c) 2018, Kontron Europe GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

/******************************************************************************
 * Traffic Analyzer
 *-----------------------------------------------------------------------------
 *
 * Description:
 *   The tool can be used to measure the bandwidth of specified traffic
 *   classes. The traffic class to measure can be defined by using PCAP
 *   filters (see "https://www.tcpdump.org/manpages/pcap-filter.7.html").
 *   The number of filters is currently limited to 16.
 *
 *   Without any filter the bandwidth of all traffic classes is measured.
 *   To specify all traffic the non-PcCAP filter "all" is used.
 *
 *   The results are sent for each specified timeout as a JSON string on
 *   STDOUT (default) or to socket.
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <pcap.h>

#include <jansson.h>
#include <glib.h>
#include <glib/gprintf.h>

#include "netsock.h"

#ifndef VERSION
#define VERSION "dev"
#endif

#define UNUSED(x) (void)x

#define DEF_INTERVAL_MSEC  1000

/* filter definitions */

#define MAX_FILTER 16

#define FILTER_EXPR_ALL "all"

typedef struct {
    gchar*             jsonName;   /* name for filter (command argument) */
    gchar*             pcapExpr;   /* PCAP expression (command argument) */
    pcap_t*            pcap;       /* (internal for PCAP)                */
    struct bpf_program bpf;        /* (internal for PCAP                 */
    gint               counter;    /* received bytes                    */
} t_pcap_filter;

static t_pcap_filter* pcapFilter[MAX_FILTER];
static gint           pcapFilterCount = 0;

static gchar *helpDescription = NULL;

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
static char *timespec_to_iso_string(struct timespec *time)
{
    GString *iso_string;
    struct tm t;
    guint32 nsec;
    char buf[32];

    if (time != NULL) {
        nsec = time->tv_nsec;
        if (gmtime_r(&(time->tv_sec), &t) == NULL) {
            return NULL;
        }
    } else {
        time_t sec = 0;
        nsec = 0;
        if (gmtime_r(&sec, &t) == NULL) {
            return NULL;
        }
    }

    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &t);
    iso_string = g_string_new_len(buf, strlen(buf));
    g_string_append_printf(iso_string, ".%09dZ", nsec);

    return g_string_free(iso_string, FALSE);
}

static void set_json_data_timestamp (json_t* pJsonObj, struct timespec* pTime,
                                     const gchar* pTimeObjName)
{
    json_t* pJsonVal;
    gchar*  pIsoTime;

    pIsoTime = timespec_to_iso_string(pTime);
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

static char* generate_statistics (gint64 intervalMsec,
                                  struct timespec* pTimeStart,
                                  struct timespec* pTimeEnd)
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
    struct timespec timeStart, timeCurrent;
    gint64 timeElapsed;
    gchar* pJsonString;

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
        init_filter (JSON_OBJ_VAL_FILTER_EXPR_NONE, FILTER_EXPR_ALL);
    }

    /* generate for each requested filter rule a separate pcap instance */
    for (idx = 0; idx < pcapFilterCount; idx++) {
        pcap = netreceive_pcap_open(pDev, intervalMsec);
        if (pcap == NULL) {
            return ENOENT;
        }
        pcapFilter[idx]->pcap = pcap;

        /* do not set a filter if no filter requested */
        if ((pcapFilter[idx]->pcapExpr == NULL) ||
            (strcmp (pcapFilter[idx]->pcapExpr, FILTER_EXPR_ALL) == 0)) {
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

    clock_gettime(CLOCK_REALTIME, &timeStart);

    /* run pcap filter and print data after specified interval */
    while (1) {

        for (idx = 0; idx < pcapFilterCount; idx++) {
            (void) pcap_dispatch (pcapFilter[idx]->pcap, 0, pcap_callback,
                                  (u_char*) &pcapFilter[idx]->counter);
        }

        clock_gettime(CLOCK_REALTIME, &timeCurrent);

        /* elapsedTime in milliseconds */
        timeElapsed  = (timeCurrent.tv_sec  - timeStart.tv_sec ) * 1000.0;
        timeElapsed += (timeCurrent.tv_nsec - timeStart.tv_nsec) / 1000000.0;

        if (timeElapsed >= intervalMsec) {
            pJsonString = generate_statistics (timeElapsed, &timeStart,
                                               &timeCurrent);
            /* the function above resets the counters if read */

            if (socketName == NULL) {
                printf("%s\n", pJsonString);
                fflush(stdout);
            } else {
                (void) write_netreceive_socket (fdSock, pJsonString);
            }
            free (pJsonString);

            /* set new start time */
            clock_gettime(CLOCK_REALTIME, &timeStart);
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
static gboolean o_version     = FALSE;

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

    { "version", 'V', 0, G_OPTION_ARG_NONE, &o_version,
      "Show version information and exit", NULL },

    { NULL, '\0', 0, 0, NULL, NULL, NULL }
};

void usage(void)
{
    g_printf("%s", helpDescription);
}

int main(int argc, char** argv)
{
    GOptionContext* optionContext;
    GError*         error = NULL;
    gchar*          dev = NULL;

    optionContext = g_option_context_new ("<interface>");
    g_option_context_set_summary(optionContext,
         "Traffic Analyzer Tool - counts received packets on a interface");
    g_option_context_add_main_entries (optionContext, optionList, NULL);
    if (!g_option_context_parse (optionContext, &argc, &argv, &error)) {
        g_print ("Option parsing failed: %s\n", error->message);
        exit (EINVAL);
    }
    helpDescription = g_option_context_get_help(optionContext, 0, NULL);
    free(optionContext);

    if (o_version) {
        printf("%s\n", VERSION);
        return 0;
    }


    if (argc < 2) {
        usage();
        return -1;
    }

    dev = argv[1];

    if (o_configFile != NULL) {
        read_config_file (o_configFile);
    }

    return netreceive_run (dev, o_intervalMsec, o_socketName);
}

/*---- end-of-file ----*/
