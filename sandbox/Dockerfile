FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    build-essential \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# 非 root 執行，降低逃逸後破壞面
RUN useradd -m -u 1000 -s /usr/sbin/nologin runner

USER 1000:1000
WORKDIR /work

# 預設 command 可被 docker run 覆蓋
CMD ["/bin/sh", "-lc", "echo sandbox ready"]
