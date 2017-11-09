/****************************************************************************
 *  Traffic Analyzer: Analyzis of ethernet packet data (declarations)
 ***************************************************************************/
#ifndef NETDATA_H_INCLUDED
#define NETDATA_H_INCLUDED

#define PROTO_ETH_TYPE   (1 << 0)
#define PROTO_UDP_DPORT  (1 << 1)

typedef struct {
     guint8  exist;
     guint16 ethType;
     guint16 udpDestPort;
} protodata_t;

void analyze_eth_packet (protodata_t* pInfo, const guint8 *packet,
                         guint32 packetLength);

#endif
