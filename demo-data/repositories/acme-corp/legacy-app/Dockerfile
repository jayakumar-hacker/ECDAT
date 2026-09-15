FROM ubuntu:18.04

RUN apt-get update && apt-get install -y libssl-dev openssl build-essential

WORKDIR /app
COPY src/ ./src/
RUN gcc -o legacy_app src/crypto_utils.c -lssl -lcrypto

CMD ["./legacy_app"]
