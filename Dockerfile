FROM debian:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libc6-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN ./configure && make

WORKDIR /build/run
CMD ["../src/services"]
