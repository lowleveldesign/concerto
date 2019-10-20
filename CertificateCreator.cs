using System;
using System.Collections.Generic;
using System.Net;
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
    public sealed class CertificateWithPrivateKey
    {
        public CertificateWithPrivateKey(X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            Certificate = certificate;
            PrivateKey = privateKey;
        }

        public X509Certificate Certificate { get; }

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

        public static CertificateWithPrivateKey CreateCACertificate(
            CertificateWithPrivateKey? issuer = null,
            string name = "Concerto")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);

            // key
            var keyPair = GenerateRsaKeyPair(secureRandom, 3072);

            var certificateGenerator = new X509V3CertificateGenerator();

            // serial number
            certificateGenerator.SetSerialNumber(GenerateRandomSerialNumber(secureRandom));

            // subject and issuer
            var subjectName = new X509Name($"O={name} CA,OU={UserName}@{MachineName},CN={name} {UserName}@{MachineName}");
            certificateGenerator.SetSubjectDN(subjectName);

            certificateGenerator.SetIssuerDN(issuer != null ? issuer.Certificate.SubjectDN : subjectName);

            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.SetNotBefore(DateTime.UtcNow);

            certificateGenerator.SetPublicKey(keyPair.Public);

            // SKID
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));

            // CA constrains, we allow one intermediate certificate if root
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true,
                new BasicConstraints(issuer == null ? 1 : 0));

            // usage
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyCertSign));

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA",
                issuer != null ? issuer.PrivateKey : keyPair.Private, secureRandom);

            return new CertificateWithPrivateKey(certificateGenerator.Generate(signatureFactory), keyPair.Private);
        }

        public static CertificateWithPrivateKey CreateCertificate(
            CertificateWithPrivateKey issuer,
            string[] hosts,
            bool client = false,
            bool ecdsa = false)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);

            // generate the key
            var keyPair = ecdsa ? GenerateEllipticCurveKeyPair(secureRandom) : 
                GenerateRsaKeyPair(secureRandom, 2048);

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
            certificateGenerator.SetIssuerDN(issuer.Certificate.SubjectDN);
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuer.Certificate.GetPublicKey())));
            

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

            foreach (var host in hosts) {
                if (IPAddress.TryParse(host, out _)) {
                    var subjectAlternativeNames = new Asn1Encodable[] { new GeneralName(GeneralName.IPAddress, host) };
                    certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false,
                        new DerSequence(subjectAlternativeNames));
                } else if (Uri.TryCreate(host, UriKind.Absolute, out _)) {
                    var subjectAlternativeNames = new Asn1Encodable[] { new GeneralName(GeneralName.UniformResourceIdentifier, host) };
                    certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false,
                        new DerSequence(subjectAlternativeNames));
                } else {
                    var subjectAlternativeNames = new Asn1Encodable[] { new GeneralName(GeneralName.DnsName, host) };
                    certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false,
                        new DerSequence(subjectAlternativeNames));
                }
            }

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", issuer.PrivateKey, secureRandom);
            return new CertificateWithPrivateKey(certificateGenerator.Generate(signatureFactory), keyPair.Private);
        }
    }
}