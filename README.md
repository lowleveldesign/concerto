
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
CA certificate (myIntCA.pem), a site certificate (www.test.com.pem), 
and a .pem file with a certificate trust chain (www.test.com-chain.pem).

### Available options

```
-ca <path-to-cert>     Specifies which CA certificate to use.
-client                Allow a client to authenticate using the certificate.
-chain                 Create a .pem file with the certificate chain.
-ecdsa                 Use Elliptic Curve key instead of RSA.
-pfx                   Save the certificate and the key in a .pfx file.
-crl <url>             URL of the CRL distribution point.
-help                  Shows the help screen.
```

## Nuget package ([Concerto](https://www.nuget.org/packages/Concerto/))

The Nuget package contains two classes: `CertificateCreator` and `CertificateFileStore`:

```csharp
public static class CertificateCreator
{
    /// <summary>
    /// Creates a CA certificate chain.
    /// </summary>
    /// <param name="name">The name that should appear on the certificate in the subject field.</param>
    /// <param name="issuer">If it's an intermediate CA, you should provide here the Root CA certificate. Otherwise, pass null.</param>
    /// <returns>A CA certificate chain with a private key of the requested certificate.</returns>
    public static CertificateChainWithPrivateKey CreateCACertificate(
        string name = "Concerto",
        CertificateChainWithPrivateKey? issuer = null);

    /// <summary>
    /// Create a certificate for domains, IP addresses, or URIs.
    /// </summary>
    /// <param name="issuer">The issuer certificate.</param>
    /// <param name="hosts">
    /// Host for which the certificate is created. Could be domains, IP addresses, or URIs.
    /// Wildcards are supported.
    /// </param>
    /// <param name="client">Defines whether this certificate will be used for client authentication.</param>
    /// <param name="ecdsa">Create Elliptic-Curve certificate.</param>
    /// <returns></returns>
    public static CertificateChainWithPrivateKey CreateCertificate(
        CertificateChainWithPrivateKey issuer,
        string[] hosts,
        bool client = false,
        bool ecdsa = false);
}
```

```csharp
public static class CertificateFileStore
{
    /// <summary>
    /// Saves certificate to a file on a disk.
    /// </summary>
    /// <param name="cert">A certificate to save.</param>
    /// <param name="path">
    /// The path to the destination file. The file extension is important and defines the format
    /// of the encoding (currently we support only PKCS12 (.pfx) and PEM (.pem) formats). If it's PEM
    /// a new file will be created next to the certificate file with a .key extension.
    /// </param>
    /// <param name="chain">
    /// Defines whether the certificate chain should be included in the certificate file.
    /// </param>
    public static void SaveCertificate(
        CertificateChainWithPrivateKey cert, 
        string path, 
        bool chain = false);

    /// <summary>
    /// Loads a certificate from a file.
    /// </summary>
    /// <param name="path">
    /// A path to the certificate file. The format of the encoding is guessed from
    /// the file extension. Only PKCS12 (.pfx) and PEM (.pem) formats are recognized.
    /// </param>
    /// <returns>The certificate representation.</returns>
    public static CertificateChainWithPrivateKey LoadCertificate(string path);
}
```
