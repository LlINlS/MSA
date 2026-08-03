#!/bin/sh
set -e
rm -f /etc/nginx/conf.d/default.conf
if [ "$TLS_ENABLED" = "true" ]; then
    cp /etc/nginx/conf.d/default.protected.conf /etc/nginx/conf.d/default.conf
else
    cp /etc/nginx/conf.d/default.unprotected.conf /etc/nginx/conf.d/default.conf
fi
rm -f /etc/nginx/conf.d/default.protected.conf /etc/nginx/conf.d/default.unprotected.conf
exec openresty -g "daemon off;"
