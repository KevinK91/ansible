#!/bin/bash
#
# evaluate free system memory from Linux based systems
#
# Date: 2007-11-12
# Author: Thomas Borger - ESG
#
# the memory check is done with following command line:
# free -m | grep buffers/cache | awk '{ print $4 }'

# get arguments

while getopts 'w:c:hp' OPT; do
  case $OPT in
    w)  int_warn=$OPTARG;;
    c)  int_crit=$OPTARG;;
    h)  hlp="yes";;
    P)  perform="yes";;
    H)  host=$OPTARG;;
    U)  user=$OPTARG;;
    p)  port=$OPTARG;;
    f)  pcpfile=$OPTARG;;
    d)  pcpdir=$OPTARG;;
    b)  backendid=$OPTARG;;
    *)  unknown="yes";;
  esac
done

# usage
HELP="
    usage: $0 [ -w value -c value -p -h ]

    syntax:

            -w --> Warning integer value
            -c --> Critical integer value
            -P --> print out performance data
            -h --> print this help screen
            -H --> hostname of the pgpool instance
                   Default hostname is localhost
            -U --> user to connect to pgpool
                   Default user is pgpool
            -p --> pcp port of pgpool pcp
                   Default port is 9898
            -f --> file which contains pcp password
            -b --> backend ID for pgpool backend connection postgres
            -d --> pcp directory file which contain the binaries
"
#Check Arguments and exit if they are not set
if [ "$hlp" = "yes" -o $# -lt 1 ]; then
  echo "$HELP"
  exit 0
fi

if [ -z "$pcpdir" ]; then
  echo "CRITICAL - -d --> pcp directory must be set"
  echo "$HELP"
  exit 2
fi
if [ -z "$pcpfile" ]; then
  echo "CRITICAL - -p --> pcp file must be set"
  echo "$HELP"
  exit 2
fi
if [ -z "$backendid" ]; then
  echo "CRITICAL - -b --> pcp backendid must be set"
  echo "$HELP"
  exit 2
fi

#Check arguments and set default values
if [ -z "$host" ]; then
  host="localhost"
fi
if [ -z "$user" ]; then
  host="pgpool"
fi
if [ -z "$port" ]; then
  host=9898
fi

export PCPPASSFILE=$pcpfile

function pcp_node_info {
  pcpresult=$($pcpdir"/pcp_node_info -h "$host" -u "$username" -p "$port" "$backendid)
  echo $pcpresult
}
