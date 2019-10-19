﻿using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace LowLevelDesign.Concerto
{
    internal static class Program
    {
        private static void SaveCertificate(CertificateWithPrivateKey certWithKey,
            string directory, string nameWithoutExtension)
        {
            using (var writer = new StreamWriter(Path.Combine(directory, $"{nameWithoutExtension}.pem"))) {
                var pem = new PemWriter(writer);
                pem.WriteObject(certWithKey.Certificate);
            }

            using (var writer = new StreamWriter(Path.Combine(directory, $"{nameWithoutExtension}.key"))) {
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
            Console.WriteLine("concerto v{0} - creates certificates for development purposes",
                Assembly.GetExecutingAssembly().GetName().Version);
            var customAttrs = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyCompanyAttribute), true);
            Debug.Assert(customAttrs.Length > 0);
            Console.WriteLine($"Copyright (C) {DateTime.Today.Year} {((AssemblyCompanyAttribute)customAttrs[0]).Company}");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine();
            // FIXME

            Console.WriteLine();
        }

        private static int Main(string[] args)
        {
            var flags = new[] { "chain", "int", "h", "?", "help" };
            var parsedArgs = CommandLineHelper.ParseArgs(flags, args);

            if (parsedArgs.ContainsKey("h") || parsedArgs.ContainsKey("help") ||
                parsedArgs.ContainsKey("?")) {
                ShowInfoAndUsage();
                return 1;
            }

            try {
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
                } else {
                    parsedArgs.TryGetValue(string.Empty, out var hostsStr);
                    var hosts = (hostsStr ?? "").Split(new [] { ',', ' ', '\t' }, 
                        StringSplitOptions.RemoveEmptyEntries);
                    if (hosts.Length == 0) {
                        throw new CommandLineArgumentException(
                            "you need to provide at least one name to create a certificate");
                    }

                    var cert = CertificateCreator.CreateCertificate(rootCertWithKey, hosts);
                    SaveCertificate(cert, Environment.CurrentDirectory, hosts[0]);
                }
                return 0;
            } catch (CommandLineArgumentException ex) {
                Console.WriteLine($"[error] {ex.Message}");
                Console.WriteLine();
                ShowInfoAndUsage();
                return 1;
            } catch (Exception ex) {
                Console.WriteLine($"[critical] {ex.Message}");
                return 1;
            }
        }
    }
}