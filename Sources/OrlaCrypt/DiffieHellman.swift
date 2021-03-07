import Foundation
import Crypto

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public protocol PublicKeyProtocol {
    var rawRepresentation: Data { get }
    
    init(rawRepresentation: Data) throws
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public protocol PrivateKey {
    associatedtype PublicKey: PublicKeyProtocol
    
    var publicKey: PublicKey { get }
    
    /// Generate a new private key
    init()

    /// Performs a Diffie-Hellman Key Agreement
    ///
    /// - Parameter publicKeyShare: The public key share
    /// - Returns: The resulting key agreement result
    func sharedSecretFromKeyAgreement(with publicKeyShare: PublicKey) throws -> SharedSecret
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension Curve25519.KeyAgreement.PrivateKey: PrivateKey {}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension Curve25519.KeyAgreement.PublicKey: PublicKeyProtocol {}
