using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace LowLevelDesign.Concerto
{
    internal static class Program
    {
        private static void SaveCertificate(CertificateWithPrivateKey certWithKey,
            string directory, string name)
        {
            using (var writer = new StreamWriter(Path.Combine(directory, $"{name}.pem"))) {
                var pem = new PemWriter(writer);
                pem.WriteObject(certWithKey.Certificate);
            }

            using (var writer = new StreamWriter(Path.Combine(directory, $"{name}.key"))) {
                var pem = new PemWriter(writer);
                pem.WriteObject(certWithKey.PrivateKey);
            }
        }

        private static CertificateWithPrivateKey ReadOrCreateCA(string certPath)
        {
            var directory = Path.GetDirectoryName(certPath) ?? Environment.CurrentDirectory;
            var baseName = Path.GetFileNameWithoutExtension(certPath);
            var keyPath = Path.Combine(directory, baseName + ".key");

            if (!File.Exists(keyPath) || !File.Exists(certPath)) {
                Console.WriteLine($"[{nameof(ReadOrCreateCA)}] missing CA certificate or key, creating a new one");
                var certWithKey = CertificateCreator.CreateCACertificate();
                SaveCertificate(certWithKey, directory, baseName);
                return certWithKey;
            }

            using var keyFileReader = File.OpenText(keyPath);
            var pemReader = new PemReader(keyFileReader);
            var pemObject = pemReader.ReadPemObject();
            // only RSA private keys for CA supported at the moment
            var rsa = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(pemObject.Content));
            var privateKey = new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent,
                rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            using var certFileStream = File.OpenRead(certPath);
            return new CertificateWithPrivateKey(
                new X509CertificateParser().ReadCertificate(certFileStream),
                privateKey
            );
        }

        private static void ShowInfoAndUsage()
        {
            // FIXME
        }

        private static void Main(string[] args)
        {
            var parsedArgs = CommandLineHelper.ParseArgs(new[] { "v", "chain", "int", "h", "?", "help" }, args);

            var rootCertWithKey = ReadOrCreateCA(parsedArgs.TryGetValue("rootCA",
                out var rootCertPath)
                ? rootCertPath
                : Path.Combine(Environment.CurrentDirectory, "rootCA.pem"));

            if (parsedArgs.ContainsKey("int")) {
                // we are creating intermediate certificate
                if (!parsedArgs.TryGetValue(string.Empty, out var certName)) {
                    throw new CommandLineArgumentException(
                        "-int: you need to provide a name for the intermediate certificate");
                }

                SaveCertificate(CertificateCreator.CreateCACertificate(rootCertWithKey, certName),
                    Environment.CurrentDirectory, certName);
            }

            foreach (var (k, v) in parsedArgs) {
                Console.WriteLine($"key = {k}, value = {v}");
            }
        }
    }
}