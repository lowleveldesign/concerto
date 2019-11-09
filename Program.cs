using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace LowLevelDesign.Concerto
{
    internal static class Program
    {
        private static readonly Assembly AppAssembly = Assembly.GetExecutingAssembly();
        private static readonly AssemblyName AppName = AppAssembly.GetName();

        private class ConcertoUsageException : Exception
        {
            public ConcertoUsageException(string message) : base(message) { }
        }

        private static void SavePkcs12Certificate(CertificateChainWithPrivateKey certChainWithKey,
            string directory, string nameWithoutExtension, bool chain)
        {
            var certFilePath = Path.Combine(directory, $"{nameWithoutExtension}.pfx");
            Console.WriteLine($"[info] saving cert to {certFilePath}");
            if (File.Exists(certFilePath)) {
                throw new ConcertoUsageException("Cert file already exists. Please remove it or switch directories.");
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
            var certChainFilePath = Path.Combine(directory, $"{nameWithoutExtension}-chain.pem");
            var keyFilePath = Path.Combine(directory, $"{nameWithoutExtension}.key");

            Console.WriteLine($"[info] saving key to {keyFilePath}");
            Console.WriteLine($"[info] saving cert to {certFilePath}");
            if (File.Exists(certFilePath) || File.Exists(keyFilePath)) {
                throw new ConcertoUsageException("Cert or key file already exists. Please remove it or switch directories.");
            }

            using (var writer = new StreamWriter(certFilePath)) {
                var pem = new PemWriter(writer);
                Debug.Assert(certChainWithKey.Certificates.Length > 0);
                pem.WriteObject(certChainWithKey.Certificates[0]);
            }

            if (chain) {
                Console.WriteLine($"[info] saving cert chain to {certChainFilePath}");
                using var writer = new StreamWriter(certChainFilePath);
                var pem = new PemWriter(writer);
                foreach (var cert in certChainWithKey.Certificates) {
                    pem.WriteObject(cert);
                }
            }

            using (var writer = new StreamWriter(keyFilePath)) {
                var pem = new PemWriter(writer);
                var keyPkcs8Format = new Pkcs8Generator(certChainWithKey.PrivateKey);
                pem.WriteObject(keyPkcs8Format);
            }
        }

        private static CertificateChainWithPrivateKey ReadOrCreateCA(string certPath)
        {
            var directory = Path.GetDirectoryName(certPath) ?? Environment.CurrentDirectory;
            var baseName = Path.GetFileNameWithoutExtension(certPath);
            var keyPath = Path.Combine(directory, baseName + ".key");
            certPath = Path.Combine(directory, baseName + ".pem");

            if (!File.Exists(keyPath) || !File.Exists(certPath)) {
                Console.WriteLine($"[info] missing CA certificate or key, creating a new one: " +
                                  $"{Path.Combine(directory, baseName + ".pem")}");
                var certWithKey = CertificateCreator.CreateCACertificate();
                SavePemCertificate(certWithKey, directory, baseName, false);
                return certWithKey;
            }

            using var keyFileReader = File.OpenText(keyPath);
            var pemReader = new PemReader(keyFileReader);
            var keyParameters = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

            using var certFileStream = File.OpenRead(certPath);
            var certificates = new X509CertificateParser().ReadCertificates(
                certFileStream).OfType<X509Certificate>().ToArray();
            return new CertificateChainWithPrivateKey(certificates, keyParameters);
        }

        private static string SanitizeFileName(string host)
        {
            return host.Replace("*", "_all")
                .Replace(":", "_")
                .Replace("/", "_");
        }

        private static void ShowInfoAndUsage()
        {
            Console.WriteLine($"{AppName.Name} v{AppName.Version} - creates certificates for development purposes");
            var customAttrs = AppAssembly.GetCustomAttributes(typeof(AssemblyCompanyAttribute), true);
            Debug.Assert(customAttrs.Length > 0);
            Console.WriteLine($"Copyright (C) {DateTime.Today.Year} {((AssemblyCompanyAttribute)customAttrs[0]).Company}");
            Console.WriteLine();
            Console.WriteLine("Certificates are always created in the current directory. If Root CA does not ");
            Console.WriteLine("exist, it will be automatically created.");
            Console.WriteLine();
            Console.WriteLine("Usage examples:");
            Console.WriteLine();
            Console.WriteLine($"  $ {AppName.Name} www.test.com");
            Console.WriteLine("  Creates a certificate for www.test.com.");
            Console.WriteLine();
            Console.WriteLine($"  $ {AppName.Name} -int my-intermediate");
            Console.WriteLine("  Creates an intermediate certificate.");
            Console.WriteLine();
            Console.WriteLine($"  $ {AppName.Name} -ca my-intermediate.pem www.test.com");
            Console.WriteLine("  Creates a certificate for www.test.com and signs it with the my-intermediate CA.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -ca <path-to-cert>     Specifies which CA certificate to use.");
            Console.WriteLine("  -client                Allow a client to authenticate using the certificate.");
            Console.WriteLine("  -chain                 Create a .pem file with the certificate chain.");
            Console.WriteLine("  -ecdsa                 Use Elliptic Curve key instead of RSA.");
            Console.WriteLine("  -pfx                   Save the certificate and the key in a .pfx file.");
            Console.WriteLine("  -crl <url>             URL of the CRL distribution point.");
            Console.WriteLine("  -help                  Shows this help screen.");
            Console.WriteLine();
        }

        private static int Main(string[] args)
        {
            var flags = new[] { "int", "client", "ecdsa", "chain", "pfx", "h", "?", "help" };
            var parsedArgs = CommandLineHelper.ParseArgs(flags, args);

            if (parsedArgs.ContainsKey("h") || parsedArgs.ContainsKey("help") ||
                parsedArgs.ContainsKey("?")) {
                ShowInfoAndUsage();
                return 1;
            }

            try {
                if (!parsedArgs.TryGetValue("ca", out var rootCertPath)) {
                    rootCertPath = Path.Combine(Environment.CurrentDirectory, "concertoCA.pem");
                }
                parsedArgs.TryGetValue("crl", out var crlUri);

                if (parsedArgs.ContainsKey("int")) {
                    // we are creating intermediate certificate
                    if (!parsedArgs.TryGetValue(string.Empty, out var certName)) {
                        throw new CommandLineArgumentException(
                            "-int: you need to provide a name for the intermediate certificate");
                    }

                    var rootCertWithKey = ReadOrCreateCA(rootCertPath);
                    SavePemCertificate(
                        CertificateCreator.CreateCACertificate(rootCertWithKey, certName, crlUri),
                        Environment.CurrentDirectory, certName, parsedArgs.ContainsKey("chain"));
                } else {
                    parsedArgs.TryGetValue(string.Empty, out var hostsStr);
                    var hosts = (hostsStr ?? "").Split(new[] { ',', ' ', '\t' },
                        StringSplitOptions.RemoveEmptyEntries);
                    if (hosts.Length == 0) {
                        throw new CommandLineArgumentException(
                            "you need to provide at least one name to create a certificate");
                    }

                    var rootCertWithKey = ReadOrCreateCA(rootCertPath);
                    var cert = CertificateCreator.CreateCertificate(rootCertWithKey, hosts,
                        parsedArgs.ContainsKey("client"), parsedArgs.ContainsKey("ecdsa"), crlUri);

                    if (parsedArgs.ContainsKey("pfx")) {
                        SavePkcs12Certificate(cert, Environment.CurrentDirectory, SanitizeFileName(hosts[0]),
                            parsedArgs.ContainsKey("chain"));
                    } else {
                        SavePemCertificate(cert, Environment.CurrentDirectory, SanitizeFileName(hosts[0]),
                            parsedArgs.ContainsKey("chain"));
                    }
                }
                return 0;
            } catch (Exception ex) when (ex is CommandLineArgumentException || ex is ConcertoUsageException) {
                Console.WriteLine($"[error] {ex.Message}");
                Console.WriteLine($"        {AppName.Name} -help to see usage info.");
                return 1;
            } catch (Exception ex) {
                Console.WriteLine($"[critical] {ex.Message}");
                Console.WriteLine("Please report this error at https://github.com/lowleveldesign/concerto/issues, " +
                                  "providing the below details.");
                Console.WriteLine("=== Details ===");
                Console.WriteLine(ex);
                Console.WriteLine();
                Console.WriteLine($"Command line: {Environment.CommandLine}");
                Console.WriteLine($"OS: {Environment.OSVersion}");
                Console.WriteLine($"x64 (OS): {Environment.Is64BitOperatingSystem}");
                Console.WriteLine($"x64 (Process): {Environment.Is64BitProcess}");
                return 1;
            }
        }
    }
}