#!/bin/sh
#
# Find a user's in/out traffic by username.
# Syntax:
#  pppoetraffic.sh <router ip> <snmp community> <snmp version> <username>
# edit by Alper

ROUTER=$1
ROCOMMUNITY=$2
SNMPVERSION=$3
USERNAME=$4

#fix snmpv2
if [ "$SNMPVERSION" == "2" ]; then
        SNMPVERSION="2c"
fi

SNMPWALK="/usr/bin/snmpwalk"
SNMPGET="/usr/bin/snmpget"
SNMPBULKWALK="/usr/bin/snmpbulkwalk"
USERLISTOID="1.3.6.1.4.1.9.10.24.1.3.2.1.2.2"
IFINDEXOID="1.3.6.1.4.1.9.10.24.1.3.2.1.11"

VPDNNUM=$($SNMPBULKWALK -v $SNMPVERSION -c $ROCOMMUNITY $ROUTER $USERLISTOID | grep "$USERNAME"  | cut -f1 -d'=' | sed 's/SNMPv2-SMI::enterprises.9.10.24.1.3.2.1.2.//')

if [ "$VPDNNUM" != "" ]
then
  IFNUM=`$SNMPGET -Oqv -v $SNMPVERSION -c $ROCOMMUNITY $ROUTER $IFINDEXOID.$VPDNNUM`
else
  IFNUM=0
fi

if [ "$IFNUM" = "0" ]
then
  INOCTETS=0
  OUTOCTETS=0
else
  INOCTETS=`$SNMPGET -Oqv -v $SNMPVERSION -c $ROCOMMUNITY $ROUTER ifInOctets.$IFNUM`
  OUTOCTETS=`$SNMPGET -Oqv -v $SNMPVERSION -c $ROCOMMUNITY $ROUTER ifOutOctets.$IFNUM`
fi

echo "in_traffic:$OUTOCTETS out_traffic:$INOCTETS"
