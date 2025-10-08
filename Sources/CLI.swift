import ArgumentParser
import CryptoKit
import Foundation
import SwiftCBOR

@main
struct SECrypt: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "A utility to encrypt files with SE-backed keys.",
        version: "1.0.0",
        subcommands: [
            Seal.self, Open.self,
        ],
    )
}

extension SECrypt {
    struct Seal: ParsableCommand {
        static let configuration =
            CommandConfiguration(abstract: "Seal data with Secure Enclave.")

        @Argument(help: "Input file.")
        var input: String

        @Argument(help: "Output file.")
        var output: String

        func run() throws {
            let inputData = try Data(contentsOf: URL(fileURLWithPath: input))
            let cryptoUtils = try CryptoUtils()
            let privateKey = try cryptoUtils.newSecureEnclavePrivateKey()
            let ephemeralKey = cryptoUtils.newEphemeralPrivateKey()
            let symmetricKey = try cryptoUtils.makeSymmetricKey(
                priv: ephemeralKey, pub: privateKey.publicKey)
            let sealedBox = try ChaChaPoly.seal(inputData, using: symmetricKey)
            let encryptedData = EncryptedData(
                ephemeralPublicKey: ephemeralKey.publicKey, privateKey: privateKey,
                sealedBox: sealedBox)

            try Data(encryptedData.encode()).write(to: URL(fileURLWithPath: output))
        }
    }

    struct Open: ParsableCommand {
        static let configuration =
            CommandConfiguration(abstract: "Open data sealed with Secure Enclave.")

        @Argument(help: "Input file.")
        var input: String

        @Argument(help: "Output file.")
        var output: String

        func run() throws {
            let inputData = try Data(contentsOf: URL(fileURLWithPath: input))
            let cryptoUtils = try CryptoUtils()
            let encryptedData = try EncryptedData(fromData: inputData)
            let symmetricKey = try cryptoUtils.makeSymmetricKey(
                priv: encryptedData.privateKey, pub: encryptedData.ephemeralPublicKey)
            let plaintext = try ChaChaPoly.open(encryptedData.sealedBox, using: symmetricKey)
            try plaintext.write(to: URL(fileURLWithPath: output))
        }
    }
}
