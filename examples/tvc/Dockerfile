FROM rust:1.94.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml README.md ./
COPY src ./src
COPY examples ./examples
RUN cargo build --locked --release -p stellar-tvc-example --bins

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /keys && chown 10001:10001 /keys
COPY --from=build /src/target/release/tvc_app /tvc_app
COPY --from=build /src/target/release/mock-turnkey /usr/local/bin/mock-turnkey
USER 10001:10001
EXPOSE 44020
ENTRYPOINT ["/tvc_app"]
