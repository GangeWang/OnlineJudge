FROM ubuntu:24.04

RUN apt update && apt install -y \
    clang \
    g++ \
    coreutils

RUN useradd -m runner
USER runner
WORKDIR /work