#!/bin/sh

while [ ! -f /data/tor/$TOR_SERVICE_NAME/hostname ]; do
   sleep 5
done

set
/scripts/start-dkg.sh &

export DRAND_PUBLIC_ADDRESS=`cat /data/tor/$TOR_SERVICE_NAME/hostname`:80
exec /usr/local/bin/entrypoint.sh $@