import XCTest
import Crypto
import OrlaCrypt

class CryptoTests: XCTestCase {
    func testPBKDF2_SHA1() throws {
        let pbkdf2 = PBKDF2<Insecure.SHA1>()
        
        func test(password: String, salt: String, match: String) {
            let hash = pbkdf2.hash(
                Array(password.utf8),
                salt: Array(salt.utf8),
                iterations: 1_000
            ).hexString
            
            XCTAssertEqual(hash, match)
        }
        
        let passes: [(String, String, String)] = [
            ("password", "longsalt", "1712d0a135d5fcd98f00bb25407035c41f01086a"),
            ("password2", "othersalt", "7a0363dd39e51c2cf86218038ad55f6fbbff6291"),
            ("somewhatlongpasswordstringthatIwanttotest", "1", "8cba8dd99a165833c8d7e3530641c0ecddc6e48c"),
            ("p", "somewhatlongsaltstringthatIwanttotest", "31593b82b859877ea36dc474503d073e6d56a33d"),
        ]
        
        passes.forEach(test)
    }
}
