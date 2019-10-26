using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace LowLevelDesign.Concerto
{
    public sealed class CertificateChainWithPrivateKey
    {
        public CertificateChainWithPrivateKey(X509Certificate[] certificates, AsymmetricKeyParameter privateKey)
        {
            Certificates = certificates;
            PrivateKey = privateKey;
        }

        public X509Certificate PrimaryCertificate => Certificates[0];

        public X509Certificate[] Certificates { get; }

        public AsymmetricKeyParameter PrivateKey { get; }
    }


    public static class CertificateCreator
    {
        private static readonly string MachineName = Environment.MachineName;
        private static readonly string UserName = Environment.UserName;

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(SecureRandom secureRandom, int strength)
        {
            var keyParameters = new KeyGenerationParameters(secureRandom, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateEllipticCurveKeyPair(SecureRandom secureRandom)
        {
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, secureRandom));
            return keyPairGenerator.GenerateKeyPair();
        }

        private static BigInteger GenerateRandomSerialNumber(SecureRandom secureRandom)
        {
            return BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.One.ShiftLeft(128), secureRandom);
        }

        private static X509Certificate[] BuildCertificateChain(X509Certificate primaryCertificate,
            X509Certificate[] issuerChain)
        {
            var certChain = new X509Certificate[issuerChain.Length + 1];
            certChain[0] = primaryCertificate;
            Array.Copy(issuerChain, 0, certChain, 1, issuerChain.Length);
            return certChain;
        }

        private static CrlDistPoint CreateCrlDistributionPoint(string uri)
        {
            var gn = new GeneralName(GeneralName.UniformResourceIdentifier, uri);
            var distributionPointname = new DistributionPointName(DistributionPointName.FullName, gn);
            var distributionPoint = new DistributionPoint(distributionPointname, null, null);
            return new CrlDistPoint(new[] {distributionPoint});
        }

        public static CertificateChainWithPrivateKey CreateCACertificate(
            CertificateChainWithPrivateKey? issuer = null,
            string name = "Concerto",
            string? crlUri = null)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);

            // key
            var keyPair = GenerateRsaKeyPair(secureRandom, 3072);

            var certificateGenerator = new X509V3CertificateGenerator();

            // serial number
            certificateGenerator.SetSerialNumber(GenerateRandomSerialNumber(secureRandom));

            // set subject
            var subjectName =
                new X509Name($"O={name} CA,OU={UserName}@{MachineName},CN={name} {UserName}@{MachineName}");
            certificateGenerator.SetSubjectDN(subjectName);

            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.SetNotBefore(DateTime.UtcNow);

            certificateGenerator.SetPublicKey(keyPair.Public);

            // issuer information
            if (issuer != null) {
                certificateGenerator.SetIssuerDN(issuer.PrimaryCertificate.SubjectDN);
                certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(
                        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuer.PrimaryCertificate
                            .GetPublicKey())));
            } else {
                certificateGenerator.SetIssuerDN(subjectName);
            }

            // SKID
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));

            // CA constrains, we allow one intermediate certificate if root
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true,
                new BasicConstraints(issuer == null ? 1 : 0));

            // usage
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            // CRL if defined
            if (issuer != null && crlUri != null && Uri.TryCreate(crlUri, UriKind.Absolute, out _)) {
                certificateGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false,
                    CreateCrlDistributionPoint(crlUri));
            }

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA",
                issuer != null ? issuer.PrivateKey : keyPair.Private, secureRandom);

            var certificate = certificateGenerator.Generate(signatureFactory);

            return new CertificateChainWithPrivateKey(
                BuildCertificateChain(certificate, issuer?.Certificates ?? new X509Certificate[0]),
                keyPair.Private);
        }

        public static CertificateChainWithPrivateKey CreateCertificate(
            CertificateChainWithPrivateKey issuer,
            string[] hosts,
            bool client = false,
            bool ecdsa = false,
            string? crlUri = null)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);

            // generate the key
            var keyPair = ecdsa ? GenerateEllipticCurveKeyPair(secureRandom) : GenerateRsaKeyPair(secureRandom, 2048);
            var certificateGenerator = new X509V3CertificateGenerator();

            // serial number
            certificateGenerator.SetSerialNumber(GenerateRandomSerialNumber(secureRandom));

            // set subject
            var subject = new X509Name($"O=concerto development,OU={UserName}@{MachineName},CN={hosts[0]}");
            certificateGenerator.SetSubjectDN(subject);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.SetNotBefore(DateTime.UtcNow);
            certificateGenerator.SetPublicKey(keyPair.Public);

            // not CA
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true,
                new BasicConstraints(false));

            // set issuer data
            certificateGenerator.SetIssuerDN(issuer.PrimaryCertificate.SubjectDN);
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuer.PrimaryCertificate.GetPublicKey())));

            // usage
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));

            var extendedKeyUsages = new List<KeyPurposeID>();
            if (client) {
                extendedKeyUsages.Add(KeyPurposeID.IdKPClientAuth);
            }

            extendedKeyUsages.Add(KeyPurposeID.IdKPServerAuth);
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id,
                false, new ExtendedKeyUsage(extendedKeyUsages));

            var subjectAlternativeNames = new List<Asn1Encodable>(hosts.Length);
            foreach (var host in hosts) {
                if (Uri.TryCreate(host, UriKind.Absolute, out _)) {
                    subjectAlternativeNames.Add(new GeneralName(GeneralName.UniformResourceIdentifier, host));
                } else {
                    var h = host.StartsWith('*') ? "wildcard" + host[1..] : host;
                    switch (Uri.CheckHostName(h)) {
                        case UriHostNameType.IPv4:
                        case UriHostNameType.IPv6:
                            subjectAlternativeNames.Add(new GeneralName(GeneralName.IPAddress, host));
                            break;
                        case UriHostNameType.Dns:
                            subjectAlternativeNames.Add(new GeneralName(GeneralName.DnsName, host));
                            break;
                        default:
                            Console.WriteLine($"[warning] unrecognized host name type: {host}");
                            break;
                    }
                }
            }

            if (subjectAlternativeNames.Count > 0) {
                certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false,
                    new DerSequence(subjectAlternativeNames.ToArray()));
            }

            // CRL if defined
            if (crlUri != null && Uri.TryCreate(crlUri, UriKind.Absolute, out _)) {
                certificateGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false,
                    CreateCrlDistributionPoint(crlUri));
            }

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", issuer.PrivateKey, secureRandom);
            var certificate = certificateGenerator.Generate(signatureFactory);

            return new CertificateChainWithPrivateKey(
                BuildCertificateChain(certificate, issuer.Certificates), keyPair.Private);
        }
    }
}