sslcheck
====

### What is it?
`sslcheck` verifies the following in SSL certificates:
 - contains private key
 - contains full chain of trust
 - expiration date
 - is wildcard certificate

Verified certificates can be used in haproxy

### How to use it?
```bash
$ sslcheck
Verify SSL certificate

Usage:
  sslcheck [command]

Available Commands:
  help        Help about any command
  serve       Start webserver on provided port
  verify      Verify SSL certificate
  version     Print version

Flags:
  -c, --cert string   certificate file
  -h, --help          help for sslcheck
  -v, --verbose       verbose output
```

#### Using curl with sslcheck HTTP server on custom port
```bash
curl --resolve *:8443:127.0.0.1 https://example.com:8443 -v
```



### How to install it?
```bash
grm install jsnjack/sslcheck
```

