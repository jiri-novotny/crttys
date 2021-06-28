# crttys
C rewrite of rttys https://github.com/zhaojh329/rttys

## Motivation
Reuse working client and add new features to server
* websocket proxy
* multiple users, no signup
* store device certs based on predefined CN prefix - device registration
* very simple web interface
* possibility to proxy web via URL only
* Device-over-DTLS

## Changes from original rttys
* Only mTLS is used for device authentication
* Token field is used as target proxy path
* Dual-cert for web pages and device connection

## Known limitations
* Web is using basic authorization which can be in collision with proxied web app
* Web proxy can fail with verly large single-page websites (>400KB)
* File transfer is not implemented
* Currently tested with ~10 devices

## Build
```make```

## Dependencies
* openssl - tested with 1.1.1f

