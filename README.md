
# concerto

A command line tool to generate TLS certificates for development purposes. 
Inspired by [mkcert](https://github.com/FiloSottile/mkcert) by Filippo Valsorda, 
but written in C# using the [Bouncy Castle](https://www.bouncycastle.org/csharp/) 
library.

### Create a site certificate

```
$ concerto www.test.com
```

This will create a concertoCA.pem root certificate and a www.test.com.pem 
certificate for your domain. You may add multiple domains, if needed. 
IPs and URIs are accepted too.

### Create a site certificate with an intermediate CA

```
$ concerto -int myIntCA
$ concerto -chain -ca myIntCA.pem www.test.com
```

This will create a concertoCA.pem root certificate, an intermediate 
CA certificate (myIntCA.pem), a site certificate (www.test.com.pem), 
and a .pem file with a certificate trust chain (www.test.com-chain.pem).

### Available options

```
-ca <path-to-cert>     Specifies which CA certificate to use.
-client                Allow a client to authenticate using the certificate.
-ecdsa                 Use Elliptic Curve key instead of RSA.
-help                  Shows this help screen.
```
