// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// simple-ca-trust adds the root CA and the issuing CAs of a simple-ca CA to the Windows
// certificate stores, removes them, and lists them.

using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

[assembly: SupportedOSPlatform("windows")]

const string Usage = """
    Usage:
      simple-ca-trust add [--user | --machine] [--ca-dir DIR]
      simple-ca-trust remove [--user | --machine] [--ca-dir DIR]
      simple-ca-trust list [--user | --machine]
      simple-ca-trust --version

    Adds the root CA of the CA in --ca-dir, read from ca_bundle.pem of its root CA, to the
    Trusted Root Certification Authorities store and its issuing CAs to the Intermediate
    Certification Authorities store, removes them, or lists the CAs it added. --ca-dir is the
    directory of the root CA or of one of its issuing CAs, or a directory holding a copy of
    ca_bundle.pem; it defaults to SIMPLE_CA_DIR, else the working directory. --user, the default,
    is the stores of the current user; --machine is the stores of the computer, and needs an
    elevated prompt.

    """;
const string LabelPrefix = "simple-ca: ";

try
{
    return Run(args);
}
catch (Failure failure) when (failure.Usage)
{
    if (failure.Message != "")
    {
        Console.Error.WriteLine(failure.Message + "\n");
    }
    Console.Error.Write(Usage);
    return 2;
}
catch (Exception error) when (error is Failure or CryptographicException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"ERROR: {error.Message}");
    return 1;
}

static int Run(string[] arguments)
{
    if (arguments.Length == 0)
    {
        throw new Failure("", usage: true);
    }
    var command = arguments[0];
    switch (command)
    {
        case "-h" or "-help" or "--help" or "help":
            Console.Write(Usage);
            return 0;
        case "-version" or "--version":
            var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            Console.WriteLine($"simple-ca-trust {version?.InformationalVersion ?? "dev"}");
            return 0;
        case "add" or "remove" or "list":
            break;
        default:
            throw new Failure($"simple-ca-trust: unknown command \"{command}\"", usage: true);
    }

    var machine = false;
    var caDir = "";
    var rest = arguments.Skip(1).ToList();
    while (rest.Count > 0 && rest[0].StartsWith('-'))
    {
        var option = rest[0];
        rest.RemoveAt(0);
        switch (option)
        {
            case "--machine" or "-machine":
                machine = true;
                break;
            case "--user" or "-user":
                machine = false;
                break;
            case "--ca-dir" or "-ca-dir":
                if (rest.Count == 0)
                {
                    throw new Failure($"simple-ca-trust {command}: {option} needs a directory", usage: true);
                }
                caDir = rest[0];
                rest.RemoveAt(0);
                break;
            case var value when value.StartsWith("--ca-dir=", StringComparison.Ordinal) || value.StartsWith("-ca-dir=", StringComparison.Ordinal):
                caDir = value[(value.IndexOf('=') + 1)..];
                break;
            case "-h" or "-help" or "--help":
                Console.Write(Usage);
                return 0;
            default:
                throw new Failure($"simple-ca-trust {command}: unknown option {option}", usage: true);
        }
    }
    if (rest.Count != 0)
    {
        throw new Failure($"simple-ca-trust {command}: wrong number of arguments", usage: true);
    }
    var location = machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;

    if (command == "list")
    {
        var rows = new List<string[]> { new[] { "ROLE", "SUBJECT", "EXPIRES", "SHA-256" } };
        foreach (var (name, role) in new[] { (StoreName.Root, "root CA"), (StoreName.CertificateAuthority, "issuing CA") })
        {
            using var store = new X509Store(name, location, OpenFlags.ReadOnly);
            foreach (var certificate in store.Certificates.Where(c => c.FriendlyName.StartsWith(LabelPrefix, StringComparison.Ordinal)))
            {
                rows.Add(new[] { role, certificate.Subject, certificate.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                    Fingerprint(certificate) });
            }
        }
        var widths = Enumerable.Range(0, 3).Select(column => rows.Max(row => row[column].Length)).ToArray();
        foreach (var row in rows)
        {
            Console.WriteLine(string.Concat(Enumerable.Range(0, 3).Select(column => row[column].PadRight(widths[column] + 2))) + row[3]);
        }
        return 0;
    }

    if (caDir == "")
    {
        caDir = Environment.GetEnvironmentVariable("SIMPLE_CA_DIR") ?? "";
    }
    var dir = Path.GetFullPath(caDir == "" ? Directory.GetCurrentDirectory() : caDir);

    // The directory of an issuing CA, whose certificate is not self-signed, is in that of its root CA.
    var caCert = Path.Combine(dir, "ca_cert.pem");
    if (File.Exists(caCert))
    {
        var certificate = ReadCertificates(caCert)[0];
        if (!certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
        {
            dir = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(dir)) ?? dir;
        }
    }
    var (root, issuing) = LoadCAs(Path.Combine(dir, "ca_bundle.pem"));
    if (machine && !Environment.IsPrivilegedProcess)
    {
        throw new Failure("changing the certificate stores of the computer needs an elevated prompt; run it as Administrator");
    }
    foreach (var (certificate, name, role) in issuing.Select(c => (c, StoreName.CertificateAuthority, "issuing CA"))
        .Prepend((root, StoreName.Root, "root CA")))
    {
        using var store = new X509Store(name, location, OpenFlags.ReadWrite);
        var present = store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);
        if (command == "add")
        {
            if (present.Count > 0)
            {
                Console.WriteLine($"{role} {certificate.Subject} is in the store already");
                continue;
            }
            certificate.FriendlyName = LabelPrefix + certificate.GetNameInfo(X509NameType.SimpleName, false);
            store.Add(certificate);
            Console.WriteLine($"{role} {certificate.Subject} added");
        }
        else
        {
            if (present.Count == 0)
            {
                Console.WriteLine($"{role} {certificate.Subject} is not in the store");
                continue;
            }
            store.RemoveRange(present);
            Console.WriteLine($"{role} {certificate.Subject} removed");
        }
    }
    return 0;
}

// LoadCAs returns the root CA in the PEM or DER file at path and the issuing CAs it signed: the
// file must hold exactly one CA certificate signed by its own key, and every other certificate
// must be a CA certificate signed by it.
static (X509Certificate2 Root, List<X509Certificate2> Issuing) LoadCAs(string path)
{
    if (!File.Exists(path))
    {
        throw new Failure($"{path}: no such file");
    }
    var certificates = ReadCertificates(path);
    X509Certificate2? root = null;
    foreach (var certificate in certificates)
    {
        if (!certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority))
        {
            throw new Failure($"{path}: {certificate.Subject} is not a CA certificate");
        }
        if (certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) && Chains(certificate, certificate))
        {
            if (root != null)
            {
                throw new Failure($"{path}: more than one root CA: {root.Subject} and {certificate.Subject}");
            }
            root = certificate;
        }
    }
    if (root == null)
    {
        throw new Failure($"{path}: no root CA, a CA certificate signed by its own key");
    }
    var issuing = new List<X509Certificate2>();
    foreach (var certificate in certificates.Where(c => c != root))
    {
        if (!Chains(certificate, root))
        {
            throw new Failure($"{path}: {certificate.Subject} is not signed by the root CA {root.Subject}");
        }
        issuing.Add(certificate);
    }
    return (root, issuing);
}

// ReadCertificates returns the certificates of the PEM file at path, or of the DER file holding one.
static List<X509Certificate2> ReadCertificates(string path)
{
    var data = File.ReadAllBytes(path);
    var text = Encoding.ASCII.GetString(data);
    var certificates = new List<X509Certificate2>();
    for (var rest = text.AsSpan(); PemEncoding.TryFind(rest, out var fields); rest = rest[fields.Location.End..])
    {
        if (rest[fields.Label].SequenceEqual("CERTIFICATE"))
        {
            certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(rest[fields.Base64Data].ToString())));
        }
    }
    if (certificates.Count == 0)
    {
        try
        {
            certificates.Add(X509CertificateLoader.LoadCertificate(data));
        }
        catch (CryptographicException)
        {
            throw new Failure($"{path}: no PEM or DER certificate");
        }
    }
    return certificates;
}

// Chains reports whether certificate is valid with anchor as its only trusted root.
static bool Chains(X509Certificate2 certificate, X509Certificate2 anchor)
{
    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(anchor);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    return chain.Build(certificate) && chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(anchor.RawData);
}

// Fingerprint returns the SHA-256 fingerprint of certificate as simple-ca ca show writes it, in
// colon-separated upper-case hexadecimal.
static string Fingerprint(X509Certificate2 certificate) => string.Join(':', SHA256.HashData(certificate.RawData).Select(b => b.ToString("X2")));

// Failure is an error simple-ca-trust reports; with usage, a wrong command line.
sealed class Failure(string message, bool usage = false) : Exception(message)
{
    public bool Usage { get; } = usage;
}
