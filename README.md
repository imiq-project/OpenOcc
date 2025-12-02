# Chrome

```sh
chrome \
  --enable-quic \
  --origin-to-force-quic-on=localhost:443 \
```

Additionally import certificate

# FAQs

Error: failed to sufficiently increase receive buffer size

```sh
wsl
sysctl -w net.core.rmem_max=7500000
sysctl -w net.core.wmem_max=7500000
```
