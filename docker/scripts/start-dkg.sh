#!/bin/sh
set
sleep 60
echo -n mysecret901234567890123456789012 > /tmp/secret-file
if [ x$DRAND_ACT_AS_LEADER = x1 ]; then 
	drand share --leader --nodes 2 --threshold 2 --period 86400s --tls-disable --secret-file /tmp/secret-file
	echo $?
	echo 'done as leader'
else
	while true; do
  		sleep 15
		drand share --connect `cat /data/tor/$DRAND_CONNECT_TO/hostname`:80 --tls-disable --secret-file /tmp/secret-file
		if [ $? = 0 ]; then
			break
		fi
	done
fi
