build:
	$(MAKE) -C nginx

image:
	docker build -t nginx-jwt .

start: image
	docker run --rm \
		--name nginx-jwt \
		-p 80:80 \
		nginx-jwt

stop:
	docker stop nginx-jwt && docker rm nginx-jwt
