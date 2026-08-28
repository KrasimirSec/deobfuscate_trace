# Multi-arch index digest for php:8.3-cli-bookworm (PHP 8.3.33). Do not use a floating tag.
FROM php:8.3-cli-bookworm@sha256:177529735599a8244b2c903522f029839dce1c2ac4be122fdc00ada4b45a20e4

RUN apt-get update && apt-get install -y --no-install-recommends \
        $PHPIZE_DEPS \
        ca-certificates \
        dnsmasq \
        libcurl4-openssl-dev \
        libzip-dev \
        python3 \
        python3-cryptography \
        tcpdump \
        zlib1g-dev \
    && docker-php-ext-install curl zip \
    && rm -rf /var/lib/apt/lists/*

# Compile the in-repo snapshot. Never git-clone evalhook at build time.
COPY vendor/php-eval-hook /usr/src/php-eval-hook
RUN cd /usr/src/php-eval-hook \
    && phpize \
    && ./configure --enable-evalhook \
    && make \
    && make install \
    && docker-php-ext-enable evalhook \
    && rm -rf /usr/src/php-eval-hook

COPY php-sandbox.ini /usr/local/etc/php/conf.d/zz-sandbox.ini
COPY entrypoint.sh prepend.php sink.py collect_domains.py dnsmasq.conf /opt/sandbox/
RUN chmod +x /opt/sandbox/entrypoint.sh /opt/sandbox/sink.py /opt/sandbox/collect_domains.py \
    && mkdir -p /logs /samples /tmp/ca

ENTRYPOINT ["/opt/sandbox/entrypoint.sh"]
