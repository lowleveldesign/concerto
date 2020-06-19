using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace LowLevelDesign.Concerto
{
    public static class CertificateFileStore
    {
        private static readonly TraceSource Logger = new TraceSource("LowLevelDesign.Concerto");

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
        public static void SaveCertificate(CertificateChainWithPrivateKey cert, string path, bool chain = false)
        {
            var extension = Path.GetExtension(path);
            var nameWithoutExtension = Path.GetFileNameWithoutExtension(path);
            var directory = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory;

            if (string.IsNullOrEmpty(extension) || string.Equals(".pem", extension, StringComparison.OrdinalIgnoreCase)) {
                SavePemCertificate(cert, directory, nameWithoutExtension, chain);
            } else if (string.Equals(".pfx", extension, StringComparison.OrdinalIgnoreCase)) {
                SavePkcs12Certificate(cert, directory, nameWithoutExtension, chain);
            } else {
                throw new ArgumentException(
                    $"Unknown certificate format. Accepted extensions for {nameof(path)} are: .pfx (PKCS12) and .pem (PEM).");
            }
        }

        private static void SavePkcs12Certificate(CertificateChainWithPrivateKey certChainWithKey,
            string directory, string nameWithoutExtension, bool chain)
        {
            var certFilePath = Path.Combine(directory, $"{nameWithoutExtension}.pfx");
            if (File.Exists(certFilePath)) {
                throw new ArgumentException("Cert file already exists. Please remove it or switch directories.");
            }

            var store = new Pkcs12StoreBuilder().Build();

            // cert chain
            var chainLen = 1;
            if (chain) {
                chainLen = certChainWithKey.Certificates.Length;
            }

            for (var i = 0; i < chainLen; i++) {
                var cert = certChainWithKey.Certificates[i];
                var certEntry = new X509CertificateEntry(cert);
                store.SetCertificateEntry(cert.SubjectDN.ToString(), certEntry);
            }

            // private key
            var primaryCert = certChainWithKey.PrimaryCertificate;
            var keyEntry = new AsymmetricKeyEntry(certChainWithKey.PrivateKey);
            store.SetKeyEntry(primaryCert.SubjectDN.ToString(), keyEntry,
                new[] { new X509CertificateEntry(primaryCert) });

            using var stream = File.OpenWrite(certFilePath);
            store.Save(stream, null, new SecureRandom());
        }

        private static void SavePemCertificate(CertificateChainWithPrivateKey certChainWithKey,
            string directory, string nameWithoutExtension, bool chain)
        {
            var certFilePath = Path.Combine(directory, $"{nameWithoutExtension}.pem");
            var keyFilePath = Path.Combine(directory, $"{nameWithoutExtension}.key");

            Logger.TraceInformation($"saving key to {keyFilePath}");
            Logger.TraceInformation($"saving cert to {certFilePath}");
            if (File.Exists(certFilePath) || File.Exists(keyFilePath)) {
                throw new ArgumentException("Cert or key file already exists. Please remove it or switch directories.");
            }


            Debug.Assert(certChainWithKey.Certificates.Length > 0);
            if (chain) {
                using var writer = new StreamWriter(certFilePath);
                var pem = new PemWriter(writer);
                foreach (var cert in certChainWithKey.Certificates) {
                    pem.WriteObject(cert);
                }
            } else {
                using var writer = new StreamWriter(certFilePath);
                var pem = new PemWriter(writer);
                pem.WriteObject(certChainWithKey.Certificates[0]);
            }

            using (var writer = new StreamWriter(keyFilePath)) {
                var pem = new PemWriter(writer);
                var keyPkcs8Format = new Pkcs8Generator(certChainWithKey.PrivateKey);
                pem.WriteObject(keyPkcs8Format);
            }
        }

        /// <summary>
        /// Loads a certificate from a file.
        /// </summary>
        /// <param name="path">
        /// A path to the certificate file. The format of the encoding is guessed from
        /// the file extension. Only PKCS12 (.pfx) and PEM (.pem) formats are recognized.
        /// </param>
        /// <returns>The certificate representation.</returns>
        public static CertificateChainWithPrivateKey LoadCertificate(string path)
        {
            if (!File.Exists(path)) {
                throw new ArgumentException($"The certificate file: '{path}' does not exist.");
            }

            return Path.GetExtension(path) switch {
                var s when string.IsNullOrEmpty(s) || string.Equals(".pem", s, StringComparison.OrdinalIgnoreCase)
                    => LoadPemCertificate(path),
                var s when string.Equals(".pfx", s, StringComparison.OrdinalIgnoreCase) => LoadPfxCertificate(path),
                var s => throw new ArgumentException(
                    $"Unknown certificate format: {s}. Accepted extensions for {nameof(path)} are: .pfx (PKCS12) and .pem (PEM).")
            };
        }

        private static CertificateChainWithPrivateKey LoadPfxCertificate(string certPath)
        {
            if (certPath == null) {
                throw new ArgumentNullException($"{nameof(certPath)}");
            }
            using var certStream = File.OpenRead(certPath);
            var store = new Pkcs12StoreBuilder().Build();
            store.Load(certStream, null);

            var aliases = store.Aliases.Cast<String>().ToArray();
            if (aliases.Length == 0) {
                throw new ArgumentException("Invalid .pfx cert (no aliases)");
            }

            var certEntries = store.GetCertificateChain(aliases[0]);
            var certificates = new X509Certificate[certEntries.Length];
            for (var i = 0; i < certEntries.Length; i++) {
                certificates[i] = certEntries[i].Certificate;
            }

            return new CertificateChainWithPrivateKey(certificates, store.GetKey(aliases[0]).Key);
        }

        private static CertificateChainWithPrivateKey LoadPemCertificate(string certPath)
        {
            if (certPath == null) {
                throw new ArgumentNullException($"{nameof(certPath)}");
            }
            var keyPath = Path.ChangeExtension(certPath, ".key");

            if (!File.Exists(keyPath)) {
                throw new ArgumentException("The key file does not exist.");
            }

            using var keyFileReader = File.OpenText(keyPath);
            var pemReader = new PemReader(keyFileReader);
            var keyParameters = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

            using var certFileStream = File.OpenRead(certPath);
            var certificates = new X509CertificateParser().ReadCertificates(certFileStream).OfType<X509Certificate>().ToArray();
            return new CertificateChainWithPrivateKey(certificates, keyParameters);
        }
    }
}