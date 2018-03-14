# Netreceive

The netreceive tool can be used to measure the bandwidth of specified traffic classes. Each traffic class to measure can be defined by using [PCAP filters](https://www.tcpdump.org/manpages/pcap-filter.7.html "PCAP filter manual").

## Synopsis

    TBD

## JSON Output


    {
      "type": "bandwidth-data",
      "object": {
        "timestamp": ""  // TBD
        "data": [
          {
            "filter-name": "all",
            "bandwidth": 1.2   // bandwidth float in MBit/s
          },
          {
            "filter-name": "video",
            "bandwidth": 1.2   // bandwidth float in MBit/s
          },
        ]
      }
    }


## Config

The filter can also be set by a configuration file.

    [VIDEO]
    filter-expression= ...  // check [PCAP filters](https://www.tcpdump.org/manpages/pcap-filter.7.h    tml "PCAP filter manual")

    [TSN]
    filter-expression= ...  // check [PCAP filters](https://www.tcpdump.org/manpages/pcap-filter.7.h    tml "PCAP filter manual")
