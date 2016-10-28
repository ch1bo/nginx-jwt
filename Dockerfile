# Docker images for nginx module development
FROM buildpack-deps:jessie-curl
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
            gcc \
            libc6-dev \
            libpcre3-dev \
            libz-dev \
            make \
            cmake \
            pkg-config \
            libssl-dev \
            libjansson-dev \
    && rm -rf /var/lib/apt/lists/*
# Install libjwt
COPY libjwt /usr/src/libjwt
WORKDIR /usr/src/libjwt
RUN cmake . -DCMAKE_INSTALL_PREFIX=/usr && make && make install
# Add nginx source
RUN mkdir -p /usr/src/nginx && \
    curl -SL http://nginx.org/download/nginx-1.11.5.tar.gz \
    | tar -xzC /usr/src/nginx
# Add module source
COPY config /usr/src/nginx/nginx-jwt/
COPY ngx_http_jwt_module.c /usr/src/nginx/nginx-jwt/
# Build with nginx from source
WORKDIR /usr/src/nginx/nginx-1.11.5
RUN ./configure \
    --prefix="/usr" \
    --conf-path="/etc/nginx/nginx.conf" \
    --pid-path="/var/run/nginx.pid" \
    --error-log-path="/var/log/nginx/error.log" \
    --http-log-path="/var/log/nginx/access.log" \
    --add-module=../nginx-jwt
RUN make && make install
RUN useradd nginx
WORKDIR /
EXPOSE 80
CMD ["nginx"]
# Custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
