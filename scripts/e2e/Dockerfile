FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip gzip openssl iproute2 procps jq \
      build-essential libpcre2-dev zlib1g-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# nginx 1.30.0 from source, same idea as vwn/core/system.py::_build_nginx_from_source
RUN cd /tmp \
 && curl -fL https://nginx.org/download/nginx-1.30.0.tar.gz -o nginx.tar.gz \
 && tar xzf nginx.tar.gz \
 && cd nginx-1.30.0 \
 && ./configure \
      --prefix=/etc/nginx \
      --sbin-path=/usr/sbin/nginx \
      --modules-path=/usr/lib/nginx/modules \
      --conf-path=/etc/nginx/nginx.conf \
      --error-log-path=/var/log/nginx/error.log \
      --http-log-path=/var/log/nginx/access.log \
      --pid-path=/run/nginx.pid \
      --lock-path=/run/nginx.lock \
      --http-client-body-temp-path=/var/cache/nginx/client_temp \
      --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
      --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
      --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
      --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
      --user=www-data --group=www-data \
      --with-compat --with-threads \
      --with-http_ssl_module --with-http_v2_module \
      --with-http_realip_module --with-http_gzip_static_module \
      --with-http_stub_status_module --with-http_dav_module \
      --with-stream --with-stream_ssl_module \
      --with-stream_realip_module --with-stream_ssl_preread_module \
 && make -j"$(nproc)" \
 && make install \
 && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
             /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
             /var/cache/nginx/scgi_temp /var/log/nginx \
 && rm -rf /tmp/nginx*

RUN nginx -V 2>&1 | grep -E 'nginx version|http_v2|http_grpc|http_ssl'

WORKDIR /spike
