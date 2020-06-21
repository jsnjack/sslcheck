sslcheck
====

### What is it?
`sslcheck` verifies SSL certificates:
 - contains private key
 - contains full chain of trust
 - expiration date

### How to use it?
```bash
$ ./sslcheck -h
Usage of ./bin/sslcheck:
  -cert string
        .pem file location. The file must include private key and full certificate chain
  -hostname string
        hostname to verify the certificate
  -port string
        If port is provided, starts HTTP server on it (default "443")
```

#### Using curl with sslcheck HTTP server on custom port
```bash
curl --resolve *:8443:127.0.0.1 https://example.com:8443 -v
```



### How to install it?
```bash
grm install jsnjack/sslcheck
```

