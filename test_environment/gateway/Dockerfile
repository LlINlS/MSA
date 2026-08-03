FROM openresty/openresty:alpine
RUN apk add --no-cache openssl bash
RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout /etc/nginx/certs/server.key \
      -out /etc/nginx/certs/server.crt \
      -days 365 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
COPY default.protected.conf   /etc/nginx/conf.d/default.protected.conf
COPY default.unprotected.conf /etc/nginx/conf.d/default.unprotected.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]