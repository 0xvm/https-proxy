Sometimes you can't have BURP, or you need something really light. Here's a full featured SNI capable HTTPS intercepting proxy that will generate a Certificate Authority cert (which you'll need to trust) and certificates for whatever you visit on-the-fly. Traffic is dumped in per-domain conversation-like logs.

run with:
```bash
$ python3 proxy-SNI-logging.py --cert ca.crt --key ca.key
```

test with:
```bash
$ curl -v --insecure --proxy http://localhost:8080 https://icanhazip.com
```

- generated certs are in `./certs`
- traffic logs are in `./traffic_logs`
