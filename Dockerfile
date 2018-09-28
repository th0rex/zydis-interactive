FROM rustlang/rust:nightly
WORKDIR /root
RUN apt-get update && apt-get install clang-4.0 libclang-4.0-dev libsodium-dev -y
COPY shared shared
COPY zycord_serenity zycord_serenity 
COPY repl repl
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
ENV CC=clang-4.0
ENV CXX=clang++-4.0
RUN cd zycord_serenity && cargo build --release 
CMD cd zycord_serenity && cargo run --release
