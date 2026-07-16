import XCTest
@testable import YueqiuElevatorSupercore

final class URISubscriptionConverterTests: XCTestCase {
    func testConvertBase64SSSubscriptionToClashYAML() {
        let uri = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:1234/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dedge.example.com#%E9%A6%99%E6%B8%AFA"
        let encoded = Data(uri.utf8).base64EncodedString()

        let yaml = URISubscriptionConverter.convertIfNeeded(encoded)

        XCTAssertNotNil(yaml)
        XCTAssertTrue(yaml?.contains("proxies:") == true)
        XCTAssertTrue(yaml?.contains("type: ss") == true)
        XCTAssertTrue(yaml?.contains("cipher: \"aes-128-gcm\"") == true)
        XCTAssertTrue(yaml?.contains("password: \"password\"") == true)
        XCTAssertTrue(yaml?.contains("plugin: obfs") == true)
        XCTAssertTrue(yaml?.contains("host: \"edge.example.com\"") == true)
        XCTAssertTrue(yaml?.contains("香港A") == true)
    }

    func testConvertBase64SSSubscriptionWithCRLFLines() {
        let metadata = "ss://YWVzLTEyOC1nY206cGFzcw@example.com:1234#%E5%89%A9%E4%BD%99%E6%B5%81%E9%87%8F%EF%BC%9A61.68%20GB"
        let node = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:1234#%E9%A6%99%E6%B8%AFA"
        let encoded = Data("\(metadata)\r\n\(node)".utf8).base64EncodedString()

        let yaml = URISubscriptionConverter.convertIfNeeded(encoded)

        XCTAssertNotNil(yaml)
        XCTAssertTrue(yaml?.contains("香港A") == true)
        XCTAssertFalse(yaml?.contains("剩余流量") == true)
        XCTAssertFalse(yaml?.contains("\\nss://") == true)
    }
}
