FROM rust

RUN USER=root cargo new --bin app
WORKDIR /app

COPY ./api/Cargo.toml /app/Cargo.toml
COPY ./Cargo.lock /app/Cargo.lock

RUN cargo build --release

COPY ./api/src /app/src
COPY ./api/.sqlx /app/.sqlx

ENV SQLX_OFFLINE=true

RUN cargo build --release

ENTRYPOINT [ "cargo", "run", "--release" ]