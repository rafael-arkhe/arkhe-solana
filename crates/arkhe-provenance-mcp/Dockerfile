FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p arkhe-provenance-mcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 arkhe
COPY --from=builder /src/target/release/arkhe-provenance-mcp /usr/local/bin/arkhe-provenance-mcp
USER arkhe
ENV RUST_LOG=info
CMD ["arkhe-provenance-mcp"]
