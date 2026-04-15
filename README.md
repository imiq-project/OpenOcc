# Chrome

```sh
google-chrome --enable-quic --origin-to-force-quic-on=localhost:443 https://localhost
```

Additionally import certificate

# FAQs

Error: failed to sufficiently increase receive buffer size

```sh
wsl
sysctl -w net.core.rmem_max=7500000
sysctl -w net.core.wmem_max=7500000
```

# SDK

```sh
 pip install git+https://github.com/imiq-project/OpenOcc.git@main#subdirectory=vehicle-sdk
```
Requires pip >= 24


# Development

## Docker
Create a compose.override.yml like this:

```yaml
services:
  server:
    build:
      dockerfile: Dockerfile.dev
    volumes:
      - ./src:/app
  client:
    build:
      dockerfile: Dockerfile.dev
    volumes:
      - ./client:/app
```

Then run `docker compose up -d` to start the containers, followed by:

```sh
docker compose exec server bash
go run .
```

And in a second terminal:

```sh
docker compose exec client sh
yarn install
npm run dev
```

## Debug WebRTC

In Firefox:
about:webrtc

In Chrome:
chrome://webrtc-internals

