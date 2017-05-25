# Docker images for nginx module development
FROM buildpack-deps:jessie-curl
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
            automake \
            gcc \
            libc6-dev \
            libjansson-dev \
            libpcre3-dev \
            libssl-dev \
            libtool \
            libz-dev \
            make \
            pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Add nginx source
RUN mkdir -p /usr/src/nginx && \
    curl -SL https://nginx.org/download/nginx-1.13.0.tar.gz \
    | tar -xzC /usr/src/nginx

# Install libjwt
COPY libjwt /usr/src/libjwt
WORKDIR /usr/src/libjwt
RUN autoreconf -i && \
    ./configure --prefix="/usr/" && \
    make && \
    make install

# Add module source
COPY config /usr/src/nginx/nginx-jwt/
COPY ngx_http_jwt_module.c /usr/src/nginx/nginx-jwt/

# Build with nginx from source
WORKDIR /usr/src/nginx/nginx-1.13.0
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
