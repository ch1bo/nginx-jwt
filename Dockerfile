# Docker images for nginx module development
FROM buildpack-deps:jessie-curl
RUN mkdir -p /usr/src/nginx && \
    curl -SL http://nginx.org/download/nginx-1.11.4.tar.gz \
    | tar -xzC /usr/src/nginx
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
            gcc \
            libc6-dev \
            libpcre3-dev \
            libz-dev \
            make \
    && rm -rf /var/lib/apt/lists/*
# Add module source
COPY . /usr/src/nginx/nginx-jwt
# Build with nginx from source
WORKDIR /usr/src/nginx/nginx-1.11.4
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
# forward request and error logs to docker log collector
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
	&& ln -sf /dev/stderr /var/log/nginx/error.log
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
# Custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
