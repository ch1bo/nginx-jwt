PWD=$(shell pwd)
build_dir=$(PWD)/build

.PHONY: build
build: nginx/Makefile
	$(MAKE) -C nginx

nginx/Makefile: nginx $(build_dir)/include/jwt.h
	cd nginx; \
	LIBJWT_INC=$(build_dir)/include LIBJWT_LIB=$(build_dir)/lib \
	./configure --prefix="." \
		--conf-path="nginx.conf" \
		--error-log-path="error.log" \
		--http-log-path="access.log" \
		--add-module=..

.PHONY: libjwt
libjwt: $(build_dir)/include/jwt.h

$(build_dir)/include/jwt.h: libjwt/Makefile
	$(MAKE) -C libjwt
	$(MAKE) -C libjwt install

libjwt/Makefile: $(build_dir)/lib/pkgconfig/jansson.pc
	cd libjwt && \
	autoreconf -i && \
	PKG_CONFIG_PATH=$(build_dir)/lib/pkgconfig ./configure --prefix="$(build_dir)"

.PHONY: jansson
jansson: $(build_dir)/lib/pkgconfig/jansson.pc

$(build_dir)/lib/pkgconfig/jansson.pc: jansson/Makefile
	$(MAKE) -C jansson
	$(MAKE) -C jansson install

jansson/Makefile:
	cd jansson && \
  autoreconf -i && \
	./configure --prefix="$(build_dir)"

nginx:
	mkdir -p nginx && \
	curl http://nginx.org/download/nginx-1.13.0.tar.gz | tar -C nginx -xz --strip-components=1

start: build
	mkdir -p tmp
	cd tmp && LD_LIBRARY_PATH=../build/lib ../nginx/objs/nginx -c ../nginx.conf

image:
	docker build -t nginx-jwt .

clean:
	$(MAKE) -C jansson clean
	$(MAKE) -C libjwt clean
	$(MAKE) -C nginx clean
	rm -rf tmp

distclean:
	$(MAKE) -C jansson distclean
	$(MAKE) -C libjwt distclean
	rm -rf nginx
