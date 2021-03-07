import Crypto
import Foundation

enum OrlaCryptError: Error {
    case encryptionFailed
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public protocol Cipher {
    /// Seals the box. This encrypts and authenticates the message. Optionally, additional data can also be authenticated.
    ///
    /// - Parameters:
    ///   - key: The key used to seal.
    ///   - message: The message to seal.
    ///   - nonce: A Nonce used for sealing.
    ///   - authenticatedData: Optional additional data to be authenticated.
    /// - Returns: The sealed box containing the ciphertext and authentication tag
    /// - Throws: An error occurred while encrypting or authenticating.
    static func encrypt<Plaintext: DataProtocol>(_ message: Plaintext, using key: SymmetricKey) throws -> Data

    /// Opens the sealed box. This decrypts and verifies the authenticity of the message,
    /// and optionally verifies the authenticity of the authenticated data.
    ///
    /// - Parameters:
    ///   - key: The key used to seal.
    ///   - sealedBox: The sealed box to open
    ///   - nonce: The nonce used for sealing
    ///   - authenticatedData: The data that was authenticated.
    /// - Returns: Returns the data, if the correct key is used and the authenticated data matches the one from the seal operation.
    /// - Throws: An error occurred while decrypting or authenticating.
    static func decrypt(_ sealedBox: Data, using key: SymmetricKey) throws -> Data
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension AES.GCM: Cipher {
    public static func encrypt<Plaintext>(_ message: Plaintext, using key: SymmetricKey) throws -> Data where Plaintext : DataProtocol {
        guard let ciphertext = try seal(message, using: key).combined else {
            throw OrlaCryptError.encryptionFailed
        }
        
        return ciphertext
    }
    
    public static func decrypt<Box: DataProtocol>(_ sealedBox: Box, using key: SymmetricKey) throws -> Data {
        let box = try SealedBox(combined: sealedBox)
        return try open(box, using: key)
    }
}
