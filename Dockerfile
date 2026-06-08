FROM rust:1-alpine AS chef
RUN apk add --no-cache musl-dev protobuf-dev
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin rauths

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/rauths /usr/local/bin/rauths
EXPOSE 3000 50051
ENTRYPOINT ["rauths"]
