#!/bin/sh
# If SSL certs are mounted, use the SSL nginx config
if [ -f /etc/nginx/ssl/cert.pem ] && [ -f /etc/nginx/ssl/key.pem ]; then
    echo "SSL certificates found — enabling HTTPS"
    cp /etc/nginx/nginx-ssl.conf /etc/nginx/conf.d/default.conf
fi

exec nginx -g 'daemon off;'
