import Foundation
import XCTest
@testable import YueqiuElevatorSupercore

final class ProxyNodeParserTests: XCTestCase {
    func testParseBase64URIProviderNodesAndCountries() {
        let uriList = """
        trojan://uuid@example.com:443?type=tcp#%F0%9F%87%AD%F0%9F%87%B0%20%5BCC%5D%20%E9%A6%99%E6%B8%AF%2001
        vless://uuid@example.com:443?type=tcp#%F0%9F%87%AF%F0%9F%87%B5%20%5BCC%5D%20%E6%97%A5%E6%9C%AC%2001
        anytls://uuid@example.com:443?type=tcp#%F0%9F%87%BA%F0%9F%87%B8%20%5BYT%5D%20%E7%BE%8E%E5%9B%BD%2001
        """
        let encoded = Data(uriList.utf8).base64EncodedString()

        let nodes = ProxyNodeParser.parseNodes(from: encoded, source: "yt")

        XCTAssertEqual(nodes.count, 3)
        XCTAssertEqual(nodes[0].country, "香港")
        XCTAssertEqual(nodes[1].country, "日本")
        XCTAssertEqual(nodes[2].country, "美国")
    }

    func testParseProxyProviderURLs() {
        let yaml = """
        proxy-providers:
          yt:
            url: "https://example.com/provider"
            type: http
        proxy-groups:
          - name: Proxy
            type: select
            include-all: true
        """

        let providers = ProxyNodeParser.parseProviderURLs(from: yaml)

        XCTAssertEqual(providers["yt"]?.absoluteString, "https://example.com/provider")
    }
}
