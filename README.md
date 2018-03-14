# Netreceive

The netreceive tool can be used to measure the bandwidth of specified traffic
classes. Each traffic class to measure can be defined by using
[PCAP filters](https://www.tcpdump.org/manpages/pcap-filter.7.html
"PCAP filter manual").

## Synopsis

    Usage:
      netreceive [OPTION...] [ <interface> ]

    Traffic Analyzer Tool - counts received packets on a interface.
    If no filter is specified all packets are counted.

    Help Options:
      -h, --help                  Show help options

    Application Options:
      -c, --config=file-name      Read the filter from specified configuration file.
      -f, --filter=filter         Set filter as <name>:<pcap-filter>. Multiply filter allowed.
      -i, --interval=interval     Interval for counting in milliseconds.
      -s, --socket=name           Write result to a socket with specified name instead of stdout

### Output

    {
       "type"   : "bandwidth-data" ,
       "object" : {
         "timestamp-start" : "<iso-time>" ,
         "timestamp-end" : "<iso-time>" ,
         "data" : [
            {
              "filter-name" : "<filterName1> ,
              "filter-expression : "<filterExpr1>,
              "byte-count" : <value-bytes1>
              "bandwidth" : <value-bandwidth1>
            },
            ...,
            {
              "filter-name" : "<filterNameN> ,
              "filter-expression : "<filterExprN>,
              "byte-count" : <value-bytesN>
              "bandwidth" : <value-bandwidthN>
            }
         ]
      }
   }

   <filterName> is the name specified in '-f' option or 'all' if
                no filter is specified.

   <filterExpr> is the PCAP filter rule specified in '-f' or empty if
                no filter isspecified or 'all' is specified.

   <iso-time>   is the UTC time in ISO format, e.g. "2018-03-14T14:27:20.476312Z"


### Configuration File

The filter can also be set by a configuration file (multiple groups allowed).

    [<filter-name>]
    filter-expression=<pcap-filter>

An example exists in "configs/filters.conf".

## Usage Examples

### Set some filters by parameters, output on STDOUT

    $ ./netreceive -f "total:" -f "tsn:ether proto 0x0808" -f "video:udp port 1234" -f "bulk:ether proto 0x080a" tia0369fa230a5

### Set the filters by a configuration file, output to STDOUT

    $ ./netreceive -c configs/filters.conf tia0369fa230a5

### Set no filter (default is counting all packets), output to socket

    $ ./netreceive -s /tmp/netreceive.sock tia0369fa230a5
