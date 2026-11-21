FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN RUSTFLAGS="-D warnings" cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/emi /usr/local/bin/emi
WORKDIR /workspace
ENTRYPOINT ["emi"]
