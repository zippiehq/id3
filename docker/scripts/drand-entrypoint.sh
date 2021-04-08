#!/bin/sh

while [ ! -f /data/tor/drand1/hostname ]; do
   sleep 5
done


export DRAND_PUBLIC_ADDRESS=`cat /data/tor/drand1/hostname`:80
exec /usr/local/bin/entrypoint.sh $@