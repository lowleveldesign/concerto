
# concerto

![](https://github.com/lowleveldesign/concerto/workflows/build/badge.svg)

A command line tool and a library to generate TLS certificates for development purposes. 

Inspired by [mkcert](https://github.com/FiloSottile/mkcert) by Filippo Valsorda, 
but written in C# using the [Bouncy Castle](https://www.bouncycastle.org/csharp/) 
library.

## Command Line Tool

### Create a site certificate

```
$ concerto www.test.com
```

This will create a concertoCA.pem root certificate and a www.test.com.pem 
certificate for your domain. You may add multiple domains, if needed. 
IPs and URIs are accepted too.

Some more examples:

```
$ concerto localhost 127.0.0.1
$ concerto '*.example.com' 192.168.0.12
$ concerto https://www.example.com 192.168.0.12
```

### Create a site certificate with an intermediate CA

```
$ concerto -int myIntCA
$ concerto -chain -ca myIntCA.pem www.test.com
```

This will create a concertoCA.pem root certificate, an intermediate 
CA certificate (myIntCA.pem), a site certificate with a certificate
trust chain (www.test.com.pem).

### Available options

```
-ca <path-to-cert>     Specifies which CA certificate to use.
-client                Allow a client to authenticate using the certificate.
-chain                 Add the certificate chain to the certificate file.
-ecdsa                 Use Elliptic Curve key instead of RSA.
-pfx                   Save the certificate and the key in a .pfx file.
-help                  Shows the help screen.
```

## NuGet package ([Concerto](https://www.nuget.org/packages/Concerto))

The NuGet package contains two classes: `CertificateCreator` and `CertificateFileStore`. They provide a straightforward API to create TLS certificates and save them to and read them from a file system.

Example usage:

```csharp

var workingDir = @"C:\temp";

CertificateChainWithPrivateKey rootCA;
if (File.Exists($@"{workingDir}\myCA.pem") && File.Exists($@"{workingDir}\myCA.key")) {
    rootCA = CertificateFileStore.LoadCertificate($@"{workingDir}\myCA.pem");
} else {
    rootCA = CertificateCreator.CreateCACertificate("MyCA");
    CertificateFileStore.SaveCertificate(rootCA, $@"{workingDir}\myCA.pem");
}

var cert = CertificateCreator.CreateCertificate(new [] { "www.test.com", "localhost" }, rootCA);
CertificateFileStore.SaveCertificate(cert, $@"{workingDir}\www.test.com.pem");
```
