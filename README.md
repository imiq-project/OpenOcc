# Chrome

```sh
google-chrome --enable-quic --origin-to-force-quic-on=localhost:443 https://localhost
```

Additionally import certificate

# Compose

```yml
services:
  server:
    command: sleep infinity
    volumes:
      - ./src:/app
```

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
