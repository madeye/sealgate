FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
RUN apt-get update && apt-get install -y --no-install-recommends git ripgrep ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY relay.mjs /opt/sealgate/relay.mjs
ENV HOME=/home/sealgate
WORKDIR /workspace
CMD ["node", "/opt/sealgate/relay.mjs"]
