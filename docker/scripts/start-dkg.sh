#!/bin/sh
set
sleep 60
echo -n mysecret901234567890123456789012 > /tmp/secret-file
drand share --connect bxghw6jzkf2kixqq.onion:80 --tls-disable --secret-file /tmp/secret-file