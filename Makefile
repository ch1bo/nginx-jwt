.PHONY: build
build: nginx/Makefile
	$(MAKE) -C nginx

start: build
	mkdir -p tmp
	cd tmp && LD_LIBRARY_PATH=../build/libjwt/lib ../nginx/objs/nginx -c ../nginx.conf

image:
	docker build -t nginx-jwt .

nginx/Makefile: nginx
	cd nginx && ./configure --prefix="." \
		--conf-path="nginx.conf" \
		--error-log-path="error.log" \
		--http-log-path="access.log" \
		--add-module=..

nginx:
	mkdir -p nginx
	curl http://nginx.org/download/nginx-1.11.5.tar.gz | tar -C nginx -xz --strip-components=1

clean:
	$(MAKE) -C nginx clean
	rm -rf tmp

distclean: clean
	rm -rf nginx
