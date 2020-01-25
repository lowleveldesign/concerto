using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace LowLevelDesign.Concerto
{
    internal static class Program
    {
        private static readonly Assembly AppAssembly = Assembly.GetExecutingAssembly();
        private static readonly AssemblyName AppName = AppAssembly.GetName();

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
                CertificateFileStore.SaveCertificate(certWithKey, certPath);
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
            Console.WriteLine("  -chain                 Add the certificate chain to the certificate file.");
            Console.WriteLine("  -ecdsa                 Use Elliptic Curve key instead of RSA.");
            Console.WriteLine("  -pfx                   Save the certificate and the key in a .pfx file.");
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

                if (parsedArgs.ContainsKey("int")) {
                    // we are creating intermediate certificate
                    if (!parsedArgs.TryGetValue(string.Empty, out var certName)) {
                        throw new CommandLineArgumentException(
                            "-int: you need to provide a name for the intermediate certificate");
                    }
                    
                    var rootCertWithKey = ReadOrCreateCA(rootCertPath);
                    CertificateFileStore.SaveCertificate(
                        CertificateCreator.CreateCACertificate(certName, rootCertWithKey),
                        Path.Combine(Environment.CurrentDirectory, certName + ".pem"),
                        parsedArgs.ContainsKey("chain"));
                } else {
                    parsedArgs.TryGetValue(string.Empty, out var hostsStr);
                    var hosts = (hostsStr ?? "").Split(new[] { ',', ' ', '\t' },
                        StringSplitOptions.RemoveEmptyEntries);
                    if (hosts.Length == 0) {
                        throw new CommandLineArgumentException(
                            "you need to provide at least one name to create a certificate");
                    }

                    var rootCertWithKey = ReadOrCreateCA(rootCertPath);
                    var cert = CertificateCreator.CreateCertificate(hosts, rootCertWithKey,
                        parsedArgs.ContainsKey("client"), parsedArgs.ContainsKey("ecdsa"));

                    var extension = parsedArgs.ContainsKey("pfx") ? ".pfx" : ".pem";
                    CertificateFileStore.SaveCertificate(cert, Path.Combine(Environment.CurrentDirectory,
                        SanitizeFileName(hosts[0]) + extension), parsedArgs.ContainsKey("chain"));
                }
                return 0;
            } catch (Exception ex) when (ex is CommandLineArgumentException || ex is ArgumentException) {
                Console.WriteLine($"[error] {ex.Message}");
                Console.WriteLine($"        {AppName.Name} -help to see usage info.");
                return 1;
            } catch (Exception ex) {
                Console.WriteLine($"[critical] {ex.Message}");
                Console.WriteLine("If this error persists, please report it at https://github.com/lowleveldesign/concerto/issues, " +
                                  "providing the below details.");
                Console.WriteLine("=== Details ===");
                Console.WriteLine($"{ex.GetType()}: {ex.Message}");
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