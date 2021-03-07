// See: https://signal.org/docs/specifications/doubleratchet/#introduction
// TODO: Header encryption

import Foundation
import Crypto

/// Encodes & decodes a ratchet header into a lossless format
/// Can be used with Codable
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public protocol DoubleRatchetHeaderEncoder {
    associatedtype C: Cipher
    
    func encodeRatchetHeader<P: PrivateKey>(_ header: RatchetMessage<P>.Header) throws -> Data
    func decodeRatchetHeader<P: PrivateKey>(from data: Data) throws -> RatchetMessage<P>.Header
    func concatenate(authenticatedData: Data, withHeader header: Data) -> Data
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public protocol DoubleRatchetKDF {
    associatedtype Hash: HashFunction
    
    func calculateRootKey(diffieHellmanSecret: SharedSecret, rootKey: SymmetricKey) throws -> SymmetricKey
    func calculateChainKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey
    func calculateMessageKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct DefaultRatchetKDF<Hash: HashFunction>: DoubleRatchetKDF {
    fileprivate let messageKeyConstant: Data
    fileprivate let chainKeyConstant: Data
    fileprivate let sharedInfo: Data
    
    public init(
        messageKeyConstant: Data,
        chainKeyConstant: Data,
        sharedInfo: Data
    ) {
        self.messageKeyConstant = messageKeyConstant
        self.chainKeyConstant = chainKeyConstant
        self.sharedInfo = sharedInfo
    }
    
    public func calculateRootKey(diffieHellmanSecret: SharedSecret, rootKey: SymmetricKey) throws -> SymmetricKey {
        diffieHellmanSecret.hkdfDerivedSymmetricKey(
            using: Hash.self,
            salt: rootKey.withUnsafeBytes { buffer in
                Data(buffer: buffer.bindMemory(to: UInt8.self))
            },
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
    }
    
    public func calculateChainKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey {
        let chainKey = HMAC<Hash>.authenticationCode(for: chainKeyConstant, using: chainKey)
        return SymmetricKey(data: chainKey)
    }
    
    public func calculateMessageKey(fromChainKey chainKey: SymmetricKey) throws -> SymmetricKey {
        let messageKey = HMAC<Hash>.authenticationCode(for: messageKeyConstant, using: chainKey)
        return SymmetricKey(data: messageKey)
    }
}

public struct RatchetAssociatedDataGenerator {
    private enum Mode {
        case constant(Data)
    }
    
    private let mode: Mode
    
    public static func constant<Raw: DataProtocol>(_ data: Raw) -> RatchetAssociatedDataGenerator {
        .init(mode: .constant(Data(data)))
    }
    
    func generateAssociatedData() -> Data {
        switch mode {
        case .constant(let data):
            return data
        }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct DoubleRatchetConfiguration<
    Hash: HashFunction,
    KDF: DoubleRatchetKDF,
    HeaderEncoder: DoubleRatchetHeaderEncoder
> {
    public typealias C = HeaderEncoder.C
    
    fileprivate let info: Data
    let kdf: KDF
    let headerEncoder: HeaderEncoder
    let headerAssociatedDataGenerator: RatchetAssociatedDataGenerator
    let maxSkippedMessageKeys: Int
    
    public init<Info: DataProtocol>(
        info: Info,
        kdf: KDF,
        headerEncoder: HeaderEncoder,
        headerAssociatedDataGenerator: RatchetAssociatedDataGenerator,
        maxSkippedMessageKeys: Int
    ) {
        self.info = Data(info)
        self.kdf = kdf
        self.headerEncoder = headerEncoder
        self.headerAssociatedDataGenerator = headerAssociatedDataGenerator
        self.maxSkippedMessageKeys = maxSkippedMessageKeys
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct SkippedKey<P: PrivateKey> {
    public let publicKey: P.PublicKey
    public let messageIndex: Int
    public let messageKey: SymmetricKey
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct DoubleRatchetHKDF<
    KDF: DoubleRatchetKDF,
    HeaderEncoder: DoubleRatchetHeaderEncoder,
    P: PrivateKey
> {
    public typealias Hash = KDF.Hash
    public typealias C = HeaderEncoder.C
    
    public struct State {
        // `RK`
        public fileprivate(set) var rootKey: SymmetricKey
        
        // `DHs`
        public fileprivate(set) var localPrivateKey: P
        
        // `DHr`
        public fileprivate(set) var remotePublicKey: P.PublicKey?
        
        // `CKs`
        public fileprivate(set) var sendingKey: SymmetricKey?
        
        // `CKr`
        public fileprivate(set) var receivingKey: SymmetricKey?
        
        // `PN`
        public fileprivate(set) var previousMessages: Int
        
        // `Ns`
        public fileprivate(set) var sentMessages: Int
        
        // `Nr`
        public fileprivate(set) var receivedMessages: Int
        
        public fileprivate(set) var skippedKeys = [SkippedKey<P>]()
        
        fileprivate init(
            secretKey: SymmetricKey,
            contactingRemote remote: P.PublicKey,
            configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>
        ) throws {
            guard secretKey.bitCount == 256 else {
                throw DoubleRatchetError.invalidRootKeySize
            }
            
            let localPrivateKey = P()
            let rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: localPrivateKey.sharedSecretFromKeyAgreement(with: remote),
                rootKey: secretKey
            )
            
            self.localPrivateKey = localPrivateKey
            self.rootKey = rootKey
            self.remotePublicKey = remote
            self.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: rootKey)
            self.receivingKey = nil
            
            self.previousMessages = 0
            self.sentMessages = 0
            self.receivedMessages = 0
        }
        
        fileprivate init(
            secretKey: SymmetricKey,
            localPrivateKey: P,
            configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>
        ) throws {
            guard secretKey.bitCount == 256 else {
                throw DoubleRatchetError.invalidRootKeySize
            }
            
            self.rootKey = secretKey
            self.localPrivateKey = localPrivateKey
            self.remotePublicKey = nil
            self.sendingKey = nil
            self.receivingKey = nil
            
            self.previousMessages = 0
            self.sentMessages = 0
            self.receivedMessages = 0
        }
    }
    
    public private(set) var state: State
    public let configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>
    
    public init(
        state: State,
        configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>
    ) {
        self.state = state
        self.configuration = configuration
    }
    
    public static func initializeSender(
        secretKey: SymmetricKey,
        contactingRemote remote: P.PublicKey,
        configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>
    ) throws -> DoubleRatchetHKDF<KDF, HeaderEncoder, P> {
        let state = try State(
            secretKey: secretKey,
            contactingRemote: remote,
            configuration: configuration
        )
        return DoubleRatchetHKDF<KDF, HeaderEncoder, P>(state: state, configuration: configuration)
    }
    
    public static func initializeRecipient(
        secretKey: SymmetricKey,
        contactedBy remote: P.PublicKey,
        localPrivateKey: P,
        configuration: DoubleRatchetConfiguration<Hash, KDF, HeaderEncoder>,
        initialMessage: RatchetMessage<P>
    ) throws -> (DoubleRatchetHKDF<KDF, HeaderEncoder, P>, Data) {
        let state = try State(secretKey: secretKey, localPrivateKey: localPrivateKey, configuration: configuration)
        var engine = DoubleRatchetHKDF<KDF, HeaderEncoder, P>(state: state, configuration: configuration)
        let plaintext = try engine.ratchetDecrypt(initialMessage)
        return (engine, plaintext)
    }
    
    public mutating func ratchetEncrypt<PlainText: DataProtocol>(_ plaintext: PlainText) throws -> RatchetMessage<P> {
        guard let sendingKey = state.sendingKey else {
            throw DoubleRatchetError.uninitializedRecipient
        }
        
        // state.CKs, mk = KDF_CK(state.CKs)
        let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: sendingKey)
        state.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: sendingKey)
        
        // header = HEADER(state.DHs, state.PN, state.Ns)
        let header = RatchetMessage<P>.Header(
            senderPublicKey: state.localPrivateKey.publicKey,
            previousChainLength: state.previousMessages,
            messageNumber: state.sentMessages
        )
        
        // state.Ns += 1
        state.sentMessages += 1
        
        // return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
        let ciphertext = try C.encrypt(plaintext, using: messageKey)
        return RatchetMessage<P>(
            header: header,
            ciphertext: ciphertext
        )
    }
    
    public mutating func ratchetDecrypt(_ message: RatchetMessage<P>) throws -> Data {
        var skippedKeys = state.skippedKeys
        defer {
            state.skippedKeys = skippedKeys
        }
        func skipMessageKeys(until keyIndex: Int) throws {
            guard let receivingKey = state.receivingKey else {
                return
            }
            
            while state.receivedMessages < keyIndex {
                let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: receivingKey)
                state.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: receivingKey)
                skippedKeys.append(
                    SkippedKey(
                        publicKey: message.header.senderPublicKey,
                        messageIndex: state.receivedMessages,
                        messageKey: messageKey
                    )
                )
                if skippedKeys.count > self.configuration.maxSkippedMessageKeys {
                    skippedKeys.removeFirst()
                }
                
                state.receivedMessages += 1
            }
        }
        
        func decodeUsingSkippedMessageKeys() throws -> Data? {
            for i in 0..<skippedKeys.count {
                let skippedKey = skippedKeys[i]
                
                if skippedKey.messageIndex == message.header.messageNumber && message.header.senderPublicKey.rawRepresentation == skippedKey.publicKey.rawRepresentation {
                    skippedKeys.remove(at: i)
                    
                    return try C.decrypt(
                        message.ciphertext,
                        using: skippedKey.messageKey
                    )
                }
            }
            
            return nil
        }
        
        func diffieHellmanRatchet() throws {
            state.previousMessages = state.sentMessages
            state.sentMessages = 0
            state.receivedMessages = 0
            state.remotePublicKey = message.header.senderPublicKey
            
            state.rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: state.localPrivateKey.sharedSecretFromKeyAgreement(with: message.header.senderPublicKey),
                rootKey: state.rootKey
            )
            state.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: state.rootKey)
            state.localPrivateKey = P()
            
            state.rootKey = try configuration.kdf.calculateRootKey(
                diffieHellmanSecret: state.localPrivateKey.sharedSecretFromKeyAgreement(with: message.header.senderPublicKey),
                rootKey: state.rootKey
            )
            state.sendingKey = try configuration.kdf.calculateChainKey(fromChainKey: state.rootKey)
        }
        
        // 1. Try skipped message keys
        if let plaintext = try decodeUsingSkippedMessageKeys() {
            return plaintext
        }
        
        // 2. Check if the publicKey matches the current key
        if message.header.senderPublicKey.rawRepresentation != state.remotePublicKey?.rawRepresentation {
            // It seems that the key is out of date, so it should be replaced
            try skipMessageKeys(until: message.header.previousChainLength)
            state.skippedKeys = skippedKeys
            try diffieHellmanRatchet()
        }
        
        // 3.a. On-mismatch, Skip ahead in message keys until max. Store all the inbetween message keys in a history
        try skipMessageKeys(until: message.header.messageNumber)
        state.skippedKeys = skippedKeys
        
        guard let receivingKey = state.receivingKey else {
            preconditionFailure("Somehow, the DHRatchet wasn't executed although the receivingKey was `nil`")
        }
        
        let messageKey = try configuration.kdf.calculateMessageKey(fromChainKey: receivingKey)
        state.receivingKey = try configuration.kdf.calculateChainKey(fromChainKey: receivingKey)
        state.receivedMessages += 1
        
        return try C.decrypt(
            message.ciphertext,
            using: messageKey
        )
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct RatchetMessage<P: PrivateKey> {
    public struct Header {
        // `dh_pair`
        public let senderPublicKey: P.PublicKey
        
        // `pn`
        public let previousChainLength: Int
        
        // `N`
        public let messageNumber: Int
        
        public init(senderPublicKey: P.PublicKey, previousChainLength: Int, messageNumber: Int) {
            self.senderPublicKey = senderPublicKey
            self.previousChainLength = previousChainLength
            self.messageNumber = messageNumber
        }
    }
    
    public let header: Header
    public let ciphertext: Data
    
    public init(header: Header, ciphertext: Data) {
        self.header = header
        self.ciphertext = ciphertext
    }
}

enum DoubleRatchetError: Error {
    case invalidRootKeySize, uninitializedRecipient, tooManySkippedMessages, invalidNonceLength
}
