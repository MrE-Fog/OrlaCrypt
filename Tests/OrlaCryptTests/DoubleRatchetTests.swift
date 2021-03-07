//
//  X3DH.swift
//  X3DH
//
//  Created by Joannis Orlandos on 22/09/2020.
//

import XCTest
import OrlaCrypt
import Crypto
import Foundation

public struct JSONRatchetHeaderEncoder: DoubleRatchetHeaderEncoder {
    public typealias C = AES.GCM
    
    struct HeaderWrapper<P: PrivateKey>: Codable {
        // `dh_pair`
        public let senderPublicKey: Data
        
        // `pn`
        public let previousChainLength: Int
        
        // `N`
        public let messageNumber: Int
    }
    
    public init() {}
    
    public func encodeRatchetHeader<P: PrivateKey>(_ header: RatchetMessage<P>.Header) throws -> Data {
        let header = HeaderWrapper<P>(
            senderPublicKey: header.senderPublicKey.rawRepresentation,
            previousChainLength: header.previousChainLength,
            messageNumber: header.messageNumber
        )
        
        return try JSONEncoder().encode(header)
    }
    
    public func decodeRatchetHeader<P: PrivateKey>(from data: Data) throws -> RatchetMessage<P>.Header {
        let header = try JSONDecoder().decode(HeaderWrapper<P>.self, from: data)
        
        return try RatchetMessage<P>.Header(
            senderPublicKey: P.PublicKey(rawRepresentation: header.senderPublicKey),
            previousChainLength: header.previousChainLength,
            messageNumber: header.messageNumber
        )
    }
    
    public func concatenate(authenticatedData: Data, withHeader header: Data) -> Data {
        let info = header + authenticatedData
        let digest = SHA256.hash(data: info)
        return digest.withUnsafeBytes { buffer in
            Data(buffer: buffer.bindMemory(to: UInt8.self))
        }
    }
}

class OneOnOneTests: XCTestCase {
    func testDoubleRatchetConversation() throws {
        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let secret = SymmetricKey(size: .bits256)
        let config = DoubleRatchetConfiguration<SHA256, DefaultRatchetKDF<SHA256>, JSONRatchetHeaderEncoder>(
            info: "protocolname".data(using: .ascii)!,
            kdf: DefaultRatchetKDF<SHA256>(
                messageKeyConstant: Data([0x00]),
                chainKeyConstant: Data([0x01]),
                sharedInfo: Data([0x02, 0x03])
            ),
            headerEncoder: JSONRatchetHeaderEncoder(),
            headerAssociatedDataGenerator: .constant("constant".data(using: .ascii)!),
            maxSkippedMessageKeys: 10
        )
        
        var sender = try DoubleRatchetHKDF<
            DefaultRatchetKDF<SHA256>,
            JSONRatchetHeaderEncoder,
            Curve25519.KeyAgreement.PrivateKey
        >.initializeSender(secretKey: secret, contactingRemote: recipientKey.publicKey, configuration: config)
        let firstMessage = try sender.ratchetEncrypt("Hello".data(using: .utf8)!)
        
        var (receiver, message) = try DoubleRatchetHKDF.initializeRecipient(
            secretKey: secret,
            contactedBy: sender.state.localPrivateKey.publicKey,
            localPrivateKey: recipientKey,
            configuration: config,
            initialMessage: firstMessage
        )
        
        XCTAssertEqual(message, "Hello".data(using: .utf8))
        
        typealias RatchetEngine = DoubleRatchetHKDF<
          DefaultRatchetKDF<SHA256>,
          JSONRatchetHeaderEncoder,
          Curve25519.KeyAgreement.PrivateKey
        >
        
        func sendMessage(_ message: (encrypted: RatchetMessage<Curve25519.KeyAgreement.PrivateKey>, raw: Data),
          to recipient: inout RatchetEngine,
          shouldFail: Bool = false
        ) throws {
            if shouldFail {
                XCTAssertThrowsError(try recipient.ratchetDecrypt(message.encrypted))
            } else {
                let decrypted = try recipient.ratchetDecrypt(message.encrypted)
                
                XCTAssertEqual(message.raw, decrypted)
            }
        }
        
        @discardableResult
        func send(
            _ message: String,
            dropPacket: Bool = false,
            shouldFail: Bool = false,
            from sender: inout RatchetEngine,
            to recipient: inout RatchetEngine
        ) throws -> (encrypted: RatchetMessage<Curve25519.KeyAgreement.PrivateKey>, raw: Data) {
            let message = message.data(using: .utf8)!
            let encrypted = try sender.ratchetEncrypt(message)
               
            if !dropPacket {
                try sendMessage((encrypted: encrypted, raw: message), to: &recipient, shouldFail: shouldFail)
            }
            
            return (encrypted: encrypted, raw: message)
        }
        
        // Test basic communication
        try send("Are you there?", from: &sender, to: &receiver)
        try send("I'm getting impatient", from: &sender, to: &receiver)
        try send("Bye!", from: &sender, to: &receiver)
        
        try send("Yes, sorry, I was busy...", from: &receiver, to: &sender)
        // Test that a missed chat message isn't a disaster
        try send("How're you doing?", dropPacket: true, from: &receiver, to: &sender)
        try send("Hello?", from: &receiver, to: &sender)
        
        // Test that someone who manages to find your private keys does not read after re-keys
        // Rekeys happen when you send a message back
        var eavesdropper = receiver
        try send("I missed your message", from: &sender, to: &receiver)
        // Eavesdropper _can_ see this, because rekey hasn't happened yet
        try send("I missed your message", from: &sender, to: &eavesdropper)
        try send("I think someone is listening into this convo.", from: &receiver, to: &sender)
        try send("That shouldn't be a problem anymore, since you wrote back!", shouldFail: true, from: &sender, to: &eavesdropper)
        try send("I don't think they know.", from: &sender, to: &receiver)
        
        let missedFromSender0 = try send("Hey, I'm offline. Do you see this?", dropPacket: true, from: &sender, to: &receiver)
        let missedFromSender1 = try send("Hello?", dropPacket: true, from: &sender, to: &receiver)
        let missedFromSender2 = try send("Okay, let me know if you see this.", dropPacket: true, from: &sender, to: &receiver)
        let missedFromReceiver0 = try send("Hey, I tried calling you.", dropPacket: true, from: &receiver, to: &sender)
        let missedFromReceiver1 = try send("Are you in the plane?", dropPacket: true, from: &receiver, to: &sender)
        
        try sendMessage(missedFromReceiver1, to: &sender)
        try sendMessage(missedFromReceiver0, to: &sender)
        try sendMessage(missedFromSender0, to: &receiver)
        try sendMessage(missedFromSender2, to: &receiver)
        try sendMessage(missedFromSender1, to: &receiver)
    }
}
