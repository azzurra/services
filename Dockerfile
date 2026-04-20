FROM debian:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libc6-dev \
        ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN python3 lang/langcomp.py && ./configure && make

WORKDIR /build/run
CMD ["../src/services"]
