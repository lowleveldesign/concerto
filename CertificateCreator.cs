using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
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
            this.Certificate = certificate;
            this.PrivateKey = privateKey;
        }
        
        public X509Certificate Certificate { get; }
        
        public AsymmetricKeyParameter PrivateKey { get; }
    }
    
    public static class CertificateCreator
    {
        private static readonly string MachineName = Environment.MachineName;
        private static readonly string UserName = Environment.UserName;
        
        public static CertificateWithPrivateKey CreateCACertificate(
            CertificateWithPrivateKey? issuer = null, 
            string name = "Concerto")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);

            // key
            var keyParameters = new KeyGenerationParameters(secureRandom, 3072);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyParameters);
            var keyPair = keyPairGenerator.GenerateKeyPair();

            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.One.ShiftLeft(128), secureRandom);
            certificateGenerator.SetSerialNumber(serialNumber);
            
            // subject and issuer
            var subjectName = new X509Name($"O={name} CA,OU={UserName}@{MachineName},CN={name} {UserName}@{MachineName}");
            certificateGenerator.SetSubjectDN(subjectName);
            
            certificateGenerator.SetIssuerDN(issuer != null ? issuer.Certificate.SubjectDN : subjectName);

            certificateGenerator.SetNotAfter(DateTime.UtcNow.AddYears(10));
            certificateGenerator.SetNotBefore(DateTime.UtcNow);

            certificateGenerator.SetPublicKey(keyPair.Public);

            // CA constrains, we allow one intermediate certificate if root
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true,
                new BasicConstraints(issuer == null ? 1 : 0));

            // usage
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyCertSign));

            // SKID
			certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, 
                new SubjectKeyIdentifierStructure(keyPair.Public));

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA",
                issuer != null ? issuer.PrivateKey : keyPair.Private, secureRandom);

            return new CertificateWithPrivateKey(certificateGenerator.Generate(signatureFactory), keyPair.Private);
        }

    }
}