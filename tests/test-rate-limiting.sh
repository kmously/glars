#!/bin/bash

# Arguments: ./script host port count


DATEBEFORE=`date +%s`;
SUCCESS=0;
FAIL=0;
SERVER=$1
PORT=$2
COUNT=$3

echo "Server is $SERVER Port is $PORT and COUNT is $COUNT"
for ((i=0; i<$COUNT; i++)); do
        echo "" | nc -w 6 --send-only $SERVER $PORT  2> /dev/null
        if [ $? = 0 ] ; then
                DATEAFTER=`date +%s`;
                SEC=$(($DATEAFTER-$DATEBEFORE));
                SUCCESS=$(($SUCCESS+1));
                echo "$SUCCESS successful connections in $SEC seconds";
        else
                DATEAFTER=`date +%s`;
                SEC=$(($DATEAFTER-$DATEBEFORE));
                FAIL=$(($FAIL+1));
#                echo "$FAIL failed connections in $SEC seconds";
        fi;
        sleep 0.2;
done;
