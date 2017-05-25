PWD=$(shell pwd)
BUILDDIR=$(PWD)/build
NGINX_VERSION=1.13.0

.PHONY: build
build: nginx/Makefile
	$(MAKE) -C nginx

nginx/Makefile: nginx $(BUILDDIR)/include/jwt.h
	cd nginx; \
	LIBJWT_INC=$(BUILDDIR)/include LIBJWT_LIB=$(BUILDDIR)/lib \
	./configure --prefix="." \
		--conf-path="nginx.conf" \
		--error-log-path="error.log" \
		--http-log-path="access.log" \
		--add-module=..

.PHONY: libjwt
libjwt: $(BUILDDIR)/include/jwt.h

$(BUILDDIR)/include/jwt.h: libjwt/Makefile
	$(MAKE) -C libjwt
	$(MAKE) -C libjwt install

libjwt/Makefile: $(BUILDDIR)/lib/pkgconfig/jansson.pc
	cd libjwt && \
	autoreconf -i && \
	PKG_CONFIG_PATH=$(BUILDDIR)/lib/pkgconfig ./configure --prefix="$(BUILDDIR)"

.PHONY: jansson
jansson: $(BUILDDIR)/lib/pkgconfig/jansson.pc

$(BUILDDIR)/lib/pkgconfig/jansson.pc: jansson/Makefile
	$(MAKE) -C jansson
	$(MAKE) -C jansson install

jansson/Makefile:
	cd jansson && \
  autoreconf -i && \
	./configure --prefix="$(BUILDDIR)"

nginx:
	mkdir -p nginx && \
	curl https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz | tar -xzC nginx --strip-components=1

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
