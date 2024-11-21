.PHONY: start stop restart compile-flexible-config build-plugins

start:
	docker-compose up -d

stop:
	docker-compose down --volumes

restart:
	docker-compose restart

compile-flexible-config:
	docker run --rm \
        -v $(CURDIR)/config/krakend:/etc/krakend/ \
        -e FC_ENABLE=1 \
        -e FC_SETTINGS=/etc/krakend/settings/dev \
        -e FC_PARTIALS=/etc/krakend/partials \
        -e FC_TEMPLATES=/etc/krakend/templates \
        -e FC_OUT=/etc/krakend/krakend.json \
        devopsfaith/krakend \
        check -c krakend.tmpl

build-plugins:
	docker run -it --rm \
        -v "$(CURDIR)/plugins:/app" \
        -w /app/krakend-tokens-validation \
        krakend/builder \
        go build -buildmode=plugin \
        -o /app/krakend-tokens-validation.so \
        /app/krakend-tokens-validation/

	docker run -it --rm \
        -v "$(CURDIR)/plugins:/app" \
        -w /app/krakend-captcha \
        krakend/builder \
        go build -buildmode=plugin \
        -o /app/krakend-captcha.so \
        /app/krakend-captcha/
