# crttys
C rewrite of rttys https://github.com/zhaojh329/rttys

## Motivation
Reuse working client and add new features to server
* websocket proxy
* multiple users, no signup
* store device certs based on predefined CN prefix - device registration
* very simple web interface - no npm deps, xterm used from unpkg.com
* possibility to proxy web via URL only
* Device-over-DTLS

## Changes from original rttys
* Only mTLS is used for device authentication
* Token field is used as target proxy path
* Dual-cert for web pages and device connection

## Known limitations
* Web is using basic authorization which can be in collision with proxied web app
* Web proxy can fail with very large single-page websites (>400KB)
* File transfer is not implemented
* Currently tested with ~10 devices

## Build
```make```

## Dependencies
* openssl - tested with 1.1.1f
* hasmap from libds https://github.com/dgraham/libds (part of repo)

## Usage
Options
```
-h/--help	    	Print this help
-a/--auth		    Basic authorization for web access
-d/--dev-port		Set port for device access
-k/--dev-key		Path to device SSL key
-c/--dev-cert		Path to device SSL cert
-v/--dev-verify		Path to device verification cert dir
-V/--dev-ssl-prefix	Set device certificate prefix
-w/--web-port		Set port for web access
-x/--web-key		Path to web SSL key
-z/--web-cert		Path to web SSL cert
-i/--index-page		Path to index page
-t/--terminal-page	Path to terminal page
```

Example
```
crttys -a `cat /usr/local/etc/crttys/auth` -d 1234 -w 443 -k /usr/local/etc/crttys/key.pem -c /usr/local/etc/crttys/cert.pem -v /usr/local/etc/crttys/devices/ -x /etc/ssl/private/ssl-cert-snakeoil.key -z /etc/ssl/certs/ssl-cert-snakeoil.pem -i /usr/local/etc/crttys/index.html -t /usr/local/etc/crttys/terminal.html
```