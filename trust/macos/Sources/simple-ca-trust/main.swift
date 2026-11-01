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

// simple-ca-trust adds the root CA and the issuing CAs of a simple-ca CA to a macOS keychain,
// trusting the root CA, removes them, and lists them.

import CryptoKit
import Foundation
import Security

/// Failure is an error simple-ca-trust reports; with usage, a wrong command line.
struct Failure: Error {
    let message: String
    var usage = false
}

/// CA is a certificate of the file: the certificate, its subject summary, its SHA-256 fingerprint,
/// and whether it is the root CA.
struct CA {
    let certificate: SecCertificate
    let subject: String
    let fingerprint: String
    let root: Bool
}

let usageText = """
    Usage:
      simple-ca-trust add [--user | --machine] [--ca-dir DIR]
      simple-ca-trust remove [--user | --machine] [--ca-dir DIR]
      simple-ca-trust list [--user | --machine]
      simple-ca-trust --version

    Adds the root CA and the issuing CAs of the CA in --ca-dir, read from ca_bundle.pem of its
    root CA, to a keychain and trusts the root CA, removes them, or lists the CAs it added.
    --ca-dir is the directory of the root CA or of one of its issuing CAs, or a directory holding
    a copy of ca_bundle.pem; it defaults to SIMPLE_CA_DIR, else the working directory. --user,
    the default, is the login keychain and the user's trust settings, and asks for the user's
    password; --machine is the System keychain and the trust settings of all users, and needs
    root.

    """

/// message returns the text of the Security framework result status.
func message(_ status: OSStatus) -> String {
    (SecCopyErrorMessageString(status, nil) as String?) ?? "error \(status)"
}

/// fingerprint returns the SHA-256 fingerprint of certificate as simple-ca ca show writes it, in
/// colon-separated upper-case hexadecimal.
func fingerprint(_ certificate: SecCertificate) -> String {
    SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02X", $0) }.joined(separator: ":")
}

/// isCA reports whether the basic constraints of certificate make it a CA.
func isCA(_ certificate: SecCertificate) -> Bool {
    let values = SecCertificateCopyValues(certificate, [kSecOIDBasicConstraints] as CFArray, nil) as? [String: [String: Any]]
    let fields = values?[kSecOIDBasicConstraints as String]?[kSecPropertyKeyValue as String] as? [[String: Any]] ?? []
    return fields.contains {
        $0[kSecPropertyKeyLabel as String] as? String == "Certificate Authority" && $0[kSecPropertyKeyValue as String] as? String == "Yes"
    }
}

/// chains reports whether certificate is valid with anchor as its only trusted root.
func chains(_ certificate: SecCertificate, to anchor: SecCertificate) -> Bool {
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else {
        return false
    }
    SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
    SecTrustSetAnchorCertificatesOnly(trust, true)
    return SecTrustEvaluateWithError(trust, nil)
}

/// isSelfSigned reports whether the subject of certificate is its issuer.
func isSelfSigned(_ certificate: SecCertificate) -> Bool {
    guard let subject = SecCertificateCopyNormalizedSubjectSequence(certificate),
        let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate)
    else {
        return false
    }
    return (subject as Data) == (issuer as Data)
}

/// certificates returns the certificates of the PEM file at path, or of the DER file holding one,
/// or nil when there is no such file.
func certificates(atPath path: String) throws -> [SecCertificate]? {
    guard FileManager.default.fileExists(atPath: path) else {
        return nil
    }
    guard let data = FileManager.default.contents(atPath: path) else {
        throw Failure(message: "\(path): cannot be read")
    }
    var ders: [Data] = []
    if let text = String(data: data, encoding: .ascii), text.contains("-----BEGIN CERTIFICATE-----") {
        for block in text.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst() {
            let body = block.components(separatedBy: "-----END CERTIFICATE-----")[0]
            guard let der = Data(base64Encoded: body, options: .ignoreUnknownCharacters) else {
                throw Failure(message: "\(path): a PEM certificate is not valid base64")
            }
            ders.append(der)
        }
    } else {
        ders.append(data)
    }
    var certificates: [SecCertificate] = []
    for der in ders {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw Failure(message: "\(path): no PEM or DER certificate")
        }
        certificates.append(certificate)
    }
    return certificates
}

/// loadCAs returns the CAs in the PEM or DER file at path, the root CA first: the file must hold
/// exactly one CA certificate signed by its own key, and every other certificate must be a CA
/// certificate signed by it.
func loadCAs(_ path: String) throws -> [CA] {
    guard let certificates = try certificates(atPath: path) else {
        throw Failure(message: "\(path): no such file")
    }
    var root: SecCertificate?
    for certificate in certificates {
        let subject = SecCertificateCopySubjectSummary(certificate) as String? ?? "?"
        if !isCA(certificate) {
            throw Failure(message: "\(path): \(subject) is not a CA certificate")
        }
        if isSelfSigned(certificate) && chains(certificate, to: certificate) {
            if let root {
                let other = SecCertificateCopySubjectSummary(root) as String? ?? "?"
                throw Failure(message: "\(path): more than one root CA: \(other) and \(subject)")
            }
            root = certificate
        }
    }
    guard let root else {
        throw Failure(message: "\(path): no root CA, a CA certificate signed by its own key")
    }
    var cas = [CA(certificate: root, subject: SecCertificateCopySubjectSummary(root) as String? ?? "?",
                  fingerprint: fingerprint(root), root: true)]
    for certificate in certificates where certificate != root {
        let subject = SecCertificateCopySubjectSummary(certificate) as String? ?? "?"
        if !chains(certificate, to: root) {
            throw Failure(message: "\(path): \(subject) is not signed by the root CA \(cas[0].subject)")
        }
        cas.append(CA(certificate: certificate, subject: subject, fingerprint: fingerprint(certificate), root: false))
    }
    return cas
}

/// keychain returns the keychain of the scope: the System keychain for machine, else the user's
/// default keychain.
@diagnose(DeprecatedDeclaration, as: ignored, reason: "SecKeychain is the only documented way to address the System keychain")
func keychain(machine: Bool) throws -> SecKeychain {
    var keychain: SecKeychain?
    let status = machine
        ? SecKeychainOpen("/Library/Keychains/System.keychain", &keychain)
        : SecKeychainCopyDomainDefault(.user, &keychain)
    guard status == errSecSuccess, let keychain else {
        throw Failure(message: "the keychain cannot be opened: \(message(status))")
    }
    return keychain
}

/// added returns the certificates simple-ca-trust added to keychain, by their label.
func added(to keychain: SecKeychain) throws -> [SecCertificate] {
    var result: CFTypeRef?
    let query: [String: Any] = [
        kSecClass as String: kSecClassCertificate,
        kSecMatchSearchList as String: [keychain],
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnRef as String: true,
        kSecReturnAttributes as String: true,
    ]
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return []
    }
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
        throw Failure(message: "the keychain cannot be searched: \(message(status))")
    }
    return items.compactMap { item in
        guard (item[kSecAttrLabel as String] as? String)?.hasPrefix("simple-ca: ") == true else {
            return nil
        }
        return item[kSecValueRef as String].map { $0 as! SecCertificate }
    }
}

func run(_ arguments: [String]) throws {
    guard let command = arguments.first else {
        throw Failure(message: "", usage: true)
    }
    switch command {
    case "-h", "-help", "--help", "help":
        print(usageText, terminator: "")
        return
    case "-version", "--version":
        print("simple-ca-trust", version)
        return
    case "add", "remove", "list":
        break
    default:
        throw Failure(message: "simple-ca-trust: unknown command \"\(command)\"", usage: true)
    }

    var machine = false
    var caDir = ""
    var rest = Array(arguments.dropFirst())
    while let option = rest.first, option.hasPrefix("-") {
        rest.removeFirst()
        switch option {
        case "--machine", "-machine":
            machine = true
        case "--user", "-user":
            machine = false
        case "--ca-dir", "-ca-dir":
            guard let value = rest.first else {
                throw Failure(message: "simple-ca-trust \(command): \(option) needs a directory", usage: true)
            }
            caDir = value
            rest.removeFirst()
        case let option where option.hasPrefix("--ca-dir=") || option.hasPrefix("-ca-dir="):
            caDir = String(option.drop(while: { $0 != "=" }).dropFirst())
        case "-h", "-help", "--help":
            print(usageText, terminator: "")
            return
        default:
            throw Failure(message: "simple-ca-trust \(command): unknown option \(option)", usage: true)
        }
    }
    if !rest.isEmpty {
        throw Failure(message: "simple-ca-trust \(command): wrong number of arguments", usage: true)
    }
    let domain: SecTrustSettingsDomain = machine ? .admin : .user
    let store = try keychain(machine: machine)

    if command == "list" {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss 'UTC'"
        var rows = [["ROLE", "SUBJECT", "EXPIRES", "SHA-256"]]
        for certificate in try added(to: store) {
            var role = "issuing CA"
            if isSelfSigned(certificate) {
                var settings: CFArray?
                role = SecTrustSettingsCopyTrustSettings(certificate, domain, &settings) == errSecSuccess
                    ? "root CA" : "root CA, not trusted"
            }
            let expires = (SecCertificateCopyNotValidAfterDate(certificate) as Date?).map { formatter.string(from: $0) } ?? "?"
            rows.append([role, SecCertificateCopySubjectSummary(certificate) as String? ?? "?", expires, fingerprint(certificate)])
        }
        let widths = (0..<3).map { column in rows.map { $0[column].count }.max()! }
        for row in rows {
            print((0..<3).map { row[$0].padding(toLength: widths[$0] + 2, withPad: " ", startingAt: 0) }.joined() + row[3])
        }
        return
    }

    if caDir.isEmpty {
        caDir = ProcessInfo.processInfo.environment["SIMPLE_CA_DIR"] ?? ""
    }
    var dir = URL(fileURLWithPath: caDir.isEmpty ? FileManager.default.currentDirectoryPath : caDir).standardizedFileURL

    // The directory of an issuing CA, whose certificate is not self-signed, is in that of its root CA.
    if let certificate = try certificates(atPath: dir.appendingPathComponent("ca_cert.pem").path)?.first,
        !isSelfSigned(certificate)
    {
        dir = dir.deletingLastPathComponent()
    }
    let cas = try loadCAs(dir.appendingPathComponent("ca_bundle.pem").path)
    if machine && getuid() != 0 {
        throw Failure(message: "changing the System keychain and the trust settings of all users needs root; run it with sudo")
    }
    if command == "add" {
        for ca in cas {
            let role = ca.root ? "root CA" : "issuing CA"
            let query: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: ca.certificate,
                kSecUseKeychain as String: store,
            ]
            let status = SecItemAdd(query as CFDictionary, nil)
            switch status {
            case errSecSuccess:
                print("\(role) \(ca.subject) added to the keychain")
            case errSecDuplicateItem:
                print("\(role) \(ca.subject) is in the keychain already")
            default:
                throw Failure(message: "\(ca.subject) cannot be added to the keychain: \(message(status))")
            }

            // The keychain labels a certificate with its subject when it is added, so the label
            // marking it as simple-ca's is set afterwards.
            let match: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecMatchSearchList as String: [store],
                kSecMatchItemList as String: [ca.certificate],
            ]
            let labelled = SecItemUpdate(match as CFDictionary, [kSecAttrLabel as String: "simple-ca: " + ca.subject] as CFDictionary)
            guard labelled == errSecSuccess else {
                throw Failure(message: "\(ca.subject) cannot be labelled in the keychain: \(message(labelled))")
            }
            if ca.root {
                let status = SecTrustSettingsSetTrustSettings(ca.certificate, domain, nil)
                guard status == errSecSuccess else {
                    throw Failure(message: "\(ca.subject) cannot be trusted: \(message(status))")
                }
                print("root CA \(ca.subject) trusted")
            }
        }
        return
    }

    let present = try added(to: store)
    for ca in cas {
        let role = ca.root ? "root CA" : "issuing CA"
        if ca.root {
            let status = SecTrustSettingsRemoveTrustSettings(ca.certificate, domain)
            if status != errSecSuccess && status != errSecItemNotFound {
                throw Failure(message: "the trust of \(ca.subject) cannot be removed: \(message(status))")
            }
        }
        guard let item = present.first(where: { fingerprint($0) == ca.fingerprint }) else {
            print("\(role) \(ca.subject) is not in the keychain")
            continue
        }
        let status = SecItemDelete([kSecClass as String: kSecClassCertificate, kSecMatchItemList as String: [item]] as CFDictionary)
        guard status == errSecSuccess else {
            throw Failure(message: "\(ca.subject) cannot be removed from the keychain: \(message(status))")
        }
        print("\(role) \(ca.subject) removed")
    }
}

do {
    try run(Array(CommandLine.arguments.dropFirst()))
} catch let failure as Failure {
    if failure.usage {
        if !failure.message.isEmpty {
            FileHandle.standardError.write(Data((failure.message + "\n\n").utf8))
        }
        FileHandle.standardError.write(Data(usageText.utf8))
        exit(2)
    }
    FileHandle.standardError.write(Data("ERROR: \(failure.message)\n".utf8))
    exit(1)
}
