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

    <filterName> is the name specified in '-f' option or 'all' if no filter is specified.

    <filterExpr> is the PCAP filter rule specified in '-f' or 'all' if no filter rule is specified.

    <iso-time>   is the UTC time in ISO format, e.g. "2018-03-14T14:27:20.476312Z"


### Configuration File

The filter can also be set by a configuration file (multiple filter allowed).

    [<filter-name>]
    filter-expression=<pcap-filter>

An example configuration exists in "configs/filters.conf".

## Usage Examples

### Set some filters by parameters

    $ ./netreceive -f "total:all" -f "tsn:ether proto 0x0808" -f "video:udp port 1234" -f "bulk:ether proto 0x080a" tia0369fa230a5

### Set the filters by a configuration file

    $ ./netreceive -c configs/filters.conf tia0369fa230a5

### Set no filter (default is counting all packets) and output to socket instead of STDOUT

    $ ./netreceive -s /tmp/netreceive.sock tia0369fa230a5

## Filter output with tool 'jq'

get 'pretty' output

    $ ./netreceive ... | jq

    Output: see section 'Output' above

extract 'timestamp-start' values

    $ ./netreceive ... | jq '.object["timestamp-start"]'

    Output: "2018-03-14T10:04:11.163273Z"
            "2018-03-14T10:04:12.163466Z"

extract 'byte-count' values for first filter (in example the total counter)

    $ ./netreceive ... | jq '.object| .data[0] | ."byte-count"'
       (or)
    $ ./netreceive ... | jq '.object| .data[0]."byte-count"'
       (or)
    $ ./netreceive ... | jq '.object.data[0]."byte-count"'

    Output: 6120
            6180

extract 'byte-count' values for all filters (each listed in a separate line)

    $ ./netreceive ... | jq '.object.data[]."byte-count"'

    Output: 6120
            6120
            0
            0
            6180
            6180
            0
            0

extract 'byte-count' values for 'TSN' counter

    $ ./netreceive ... | jq '.object.data[] | if ."filter-name" == "TSN" then ."byte-count" else empty end'

    Output: 6120
            6180

extrace 'byte-count' values for all counter (above) and combine in a string

    $ ./netreceive ... | jq 'reduce (.object.data[]."byte-count" | tostring) as $item ("counter"; . + "," + $item)'

    Output: "counter,6120,6120,0,0"
            "counter,6180,6180,0,0"

extract 'timestamp-end' and 'byte-count' values for first filter
(Note: each value is printed in separate line)

    $ ./netreceive ... | jq '.object["timestamp-end"] , .object.data[0]."byte-count"'

    Output: "2018-03-14T10:04:11.163273Z"
            6120
            "2018-03-14T10:04:12.163466Z"
            6180

extract 'timestamp-end' and 'byte-count' values for first filter and generate new object

    $ ./netreceive ... | jq '{ "time" : .object["timestamp-end"] , "count": .object.data[0]."byte-count" }'

    Output: {
              "time": "2018-03-14T10:04:11.163273Z",
              "count": 6120
            }
            {
              "time": "2018-03-14T10:04:12.163466Z",
              "count": 6180
            }

you may also manipulate the result string and use internal functions,
e.g. extract the timestamp values (are in ISO format), delete the milliseconds and
transform in seconds since UNIX epoch. Note, that the function 'fromdate'
doesn't support milliseconds in the ISO format currently.

    $ ./netreceive ... | jq '.object["timestamp-start"] | gsub("[.][0-9]+"; "") | fromdate'

    Output: 1521108599
            1521108600
