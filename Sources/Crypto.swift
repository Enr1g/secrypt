import CryptoKit
import LocalAuthentication
import SwiftCBOR

protocol PrivateKeyForDH {
    var publicKey: P256.KeyAgreement.PublicKey { get }

    func sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey) throws
        -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: PrivateKeyForDH {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: PrivateKeyForDH {}

// https://stackoverflow.com/a/53296718
extension Data {
    static func ^ (left: Data, right: Data) -> Data {
        var result: Data = Data()
        var smaller: Data
        var bigger: Data

        if left.count <= right.count {
            smaller = left
            bigger = right
        } else {
            smaller = right
            bigger = left
        }

        let bs: [UInt8] = Array(smaller)
        let bb: [UInt8] = Array(bigger)
        var br = [UInt8]()

        for i in 0..<bs.count {
            br.append(bs[i] ^ bb[i])
        }

        for j in bs.count..<bb.count {
            br.append(bb[j])
        }

        result = Data(br)

        return result
    }
}

class CryptoUtils {
    let context = LAContext()
    let defaultSecAccessControl: SecAccessControl

    public init() throws {
        let accessControlFlags: SecAccessControlCreateFlags = [
            .privateKeyUsage, .userPresence,
        ]
        var error: Unmanaged<CFError>?

        guard
            let secAccessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                accessControlFlags,
                &error)
        else {
            throw error!.takeRetainedValue() as Swift.Error
        }

        self.defaultSecAccessControl = secAccessControl
    }

    var isSecureEnclaveAvailable: Bool {
        return SecureEnclave.isAvailable
    }

    func SecureEnclavePrivateKeyFromDataRepresentation(dataRepresentation: Data) throws
        -> SecureEnclave.P256.KeyAgreement.PrivateKey
    {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: dataRepresentation, authenticationContext: context)
    }

    func newSecureEnclavePrivateKey(secAccessControl: SecAccessControl? = nil) throws
        -> SecureEnclave.P256.KeyAgreement.PrivateKey
    {
        let secAccessControl = secAccessControl ?? self.defaultSecAccessControl

        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: secAccessControl, authenticationContext: context)
    }

    func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
        return P256.KeyAgreement.PrivateKey()
    }

    func makeSymmetricKey(priv: PrivateKeyForDH, pub: P256.KeyAgreement.PublicKey) throws
        -> SymmetricKey
    {
        let sharedSecret = try priv.sharedSecretFromKeyAgreement(with: pub)

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: priv.publicKey.compressedRepresentation ^ pub.compressedRepresentation,
            sharedInfo: Data("se-crypt/1.0".utf8),
            outputByteCount: 32,
        )
    }
}

struct EncryptedData: CBOREncodable {
    var ephemeralPublicKey: P256.KeyAgreement.PublicKey
    var privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    var sealedBox: ChaChaPoly.SealedBox

    enum SECryptCBORDecodeError: Error {
        case noEphemeralPublicKey
        case noPrivateKey
        case noSealedBox
    }

    public func toCBOR(options: CBOROptions = CBOROptions()) -> CBOR {
        return [
            "ephemeralPublicKey": CBOR.byteString(
                Array(ephemeralPublicKey.compressedRepresentation)),
            "privateKey": CBOR.byteString(Array(privateKey.dataRepresentation)),
            "sealedBox": CBOR.byteString(Array(sealedBox.combined)),
        ]
    }

    func encode(options: CBOROptions = CBOROptions()) -> [UInt8] {
        return self.toCBOR(options: options).encode(options: options)
    }

    public init(
        ephemeralPublicKey: P256.KeyAgreement.PublicKey,
        privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, sealedBox: ChaChaPoly.SealedBox
    ) {
        self.ephemeralPublicKey = ephemeralPublicKey
        self.sealedBox = sealedBox
        self.privateKey = privateKey
    }

    public init(fromData: Data) throws {
        let decoded = try CBOR.decode(Array(fromData))!

        if case CBOR.byteString(let epk) = decoded["ephemeralPublicKey"]! {
            self.ephemeralPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: epk)
        } else {
            throw SECryptCBORDecodeError.noEphemeralPublicKey
        }

        if case CBOR.byteString(let pk) = decoded["privateKey"]! {
            self.privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(pk))
        } else {
            throw SECryptCBORDecodeError.noPrivateKey
        }

        if case CBOR.byteString(let sb) = decoded["sealedBox"]! {
            self.sealedBox = try ChaChaPoly.SealedBox(combined: sb)
        } else {
            throw SECryptCBORDecodeError.noSealedBox
        }
    }
}
