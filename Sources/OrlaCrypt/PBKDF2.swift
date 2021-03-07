import Foundation
import Crypto

/// The requested amount of output bytes from the key derivation
///
/// In circumstances with low iterations the amount of output bytes may not be met.
///
/// `digest.digestSize * iterations` is the amount of bytes stored in PBKDF2's buffer.
/// Any data added beyond this limit
///
/// WARNING: Do not switch these key sizes, new sizes may be added
public enum PBKDF2KeySize: ExpressibleByIntegerLiteral {
    case digestSize
    case fixed(Int)
    
    public init(integerLiteral value: Int) {
        self = .fixed(value)
    }
    
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
    fileprivate func size<H: HashFunction>(for digest: H.Type) -> Int {
        switch self {
        case .digestSize:
            return numericCast(H.Digest.byteCount)
        case .fixed(let size):
            return size
        }
    }
}

/// PBKDF2 derives a fixed or custom length key from a password and salt.
///
/// It accepts a customizable amount of iterations to increase the algorithm weight and security.
///
/// Unlike BCrypt, the salt does not get stored in the final result,
/// meaning it needs to be generated and stored manually.
///
///     let passwordHasher = PBKDF2(digest: SHA1)
///     let salt = try CryptoRandom().generateData(count: 64) // Data
///     let hash = try passwordHasher.deriveKey(fromPassword: "secret", salt: salt, iterations: 15_000) // Data
///     print(hash.hexEncodedString()) // 8e55fa3015da583bb51b706371aa418afc8a0a44
///
/// PBKDF2 leans on HMAC for each iteration and can use all hash functions supported in Crypto
///
/// https://en.wikipedia.org/wiki/PBKDF2
@available(iOS 13.2, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
public struct PBKDF2<H: HashFunction> {
    /// Creates a new PBKDF2 derivator based on a hashing algorithm
    public init() {}
    
    /// Derives a key with up to `keySize` of bytes
    public func hash<Password: DataProtocol, Salt: DataProtocol>(
        _ password: Password,
        salt: Salt,
        iterations: Int32,
        keySize: PBKDF2KeySize = .digestSize
    ) -> [UInt8] {
        precondition(iterations > 0, "You must iterate in PBKDF2 at least once")
        precondition(password.count > 0, "You cannot hash an empty password")
        precondition(salt.count > 0, "You cannot hash with an empty salt")
        
        let keySize = keySize.size(for: H.self)
        
        precondition(keySize <= Int(((pow(2,32) as Double) - 1) * Double(H.blockByteCount)))
        
        let saltSize = salt.count
        var salt = salt + [0, 0, 0, 0]
        
        var passwordData: Data
        
        if password.count > H.blockByteCount {
            passwordData = Data(H.hash(data: password))
        } else if password.count < H.blockByteCount {
            passwordData = Data(password)
            
            for _ in password.count..<H.blockByteCount {
                passwordData.append(0x00)
            }
        } else {
            passwordData = Data(password)
        }
        
        var outerPadding = [UInt8](repeating: 0x5c, count: H.blockByteCount)
        var innerPadding = [UInt8](repeating: 0x36, count: H.blockByteCount)
        
        for i in 0..<passwordData.count {
            let byte = passwordData[i]
            outerPadding[i] ^= byte
            innerPadding[i] ^= byte
        }
        
        func authenticate<Message: ContiguousBytes>(message: Message) -> H.Digest {
            var hash = H()
            innerPadding.withUnsafeBytes { innerPadding in
                hash.update(bufferPointer: innerPadding)
            }
            message.withUnsafeBytes { message in
                hash.update(bufferPointer: message)
            }
            
            let innerPaddingHash = hash.finalize()
            
            hash = H()
            outerPadding.withUnsafeBytes { outerPadding in
                hash.update(bufferPointer: outerPadding)
            }
            innerPaddingHash.withUnsafeBytes { innerPaddingHash in
                hash.update(bufferPointer: innerPaddingHash)
            }
            return hash.finalize()
        }
        
        var output = [UInt8]()
        output.reserveCapacity(keySize)
        
        func calculate(block: UInt32) {
            salt.withUnsafeMutableBytes { salt in
                salt.baseAddress!.advanced(by: saltSize).assumingMemoryBound(to: UInt32.self).pointee = block.bigEndian
            }
            
            var ui = authenticate(message: salt)
            var u1 = Array(ui)
            
            if iterations > 1 {
                for _ in 1..<iterations {
                    ui = authenticate(message: ui)
                    
                    ui.withUnsafeBytes { ui in
                        for i in 0..<H.Digest.byteCount {
                            u1[i] ^= ui[i]
                        }
                    }
                }
            }
            
            output.append(contentsOf: u1)
        }
        
        for block in 1...UInt32((keySize + H.Digest.byteCount - 1) / H.Digest.byteCount) {
            calculate(block: block)
        }
        
        let extra = output.count &- keySize
        
        if extra >= 0 {
            output.removeLast(extra)
            return output
        }
        
        return output
    }
}
