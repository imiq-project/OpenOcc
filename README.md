# Chrome:
chrome \
  --enable-quic \
  --origin-to-force-quic-on=localhost:443 \
Addionally import certificate

# Firefox

about:config
network.http.http3.alt-svc-mapping-for-testing
localhost;h3=":4433"
