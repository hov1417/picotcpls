#!/bin/bash
TIME=$1
IP_SRC_1=10.0.0.1
IP_SRC_2=10.0.1.1
IP_DEST_1=10.1.0.1
IP_DEST_2=10.1.1.1
PATH=0
sleep 5
printf "Starting to backhole traffic\n"
while true;
do
  if [ $PATH -eq 0 ]
  then
    print "Blackholing Path 0\n"
    iptables -A FORWARD -p tcp -s $IP_SRC_1 -d $IP_DEST_1 -j DROP
    PATH=1
  else
    print "Blackholing Path 1\n"
    iptables -A FORWARD -p tcp -s $IP_SRC_2 -d $IP_DEST_2 -j DROP
    PATH=0
  fi
  sleep $TIME
  iptables-F
done

