build:
	docker build -t nginx-jwt .

start: build
	docker run -d \
		--name nginx-jwt \
		-p 80:80 \
		nginx-jwt

stop:
	docker stop nginx-jwt && docker rm nginx-jwt
