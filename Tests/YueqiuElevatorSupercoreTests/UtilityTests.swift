import XCTest
@testable import YueqiuElevatorSupercore

final class UtilityTests: XCTestCase {
    func testURLMaskerRedactsQueryValues() {
        let masked = URLMasker.mask("https://example.com/sub?token=abc&user=chen")
        XCTAssertTrue(masked.contains("token=%3Credacted%3E") || masked.contains("token=<redacted>"))
        XCTAssertFalse(masked.contains("abc"))
    }

    func testLogRedactorRedactsBearer() {
        let line = LogRedactor.redact("Authorization: Bearer abc.def token=hello")
        XCTAssertFalse(line.contains("abc.def"))
        XCTAssertFalse(line.contains("hello"))
    }

    func testDelayPolicyTreatsFiveHundredMillisecondsAsTimeout() {
        XCTAssertTrue(DelayPolicy.isAvailable(499))
        XCTAssertFalse(DelayPolicy.isAvailable(500))
        XCTAssertFalse(DelayPolicy.isAvailable(-1))
        XCTAssertEqual(DelayPolicy.displayTitle(for: 500), "超时")
        XCTAssertEqual(DelayPolicy.probeURL, "http://www.gstatic.com/generate_204")
    }

    func testLogClassifierSeparatesDirectRuleAndProxyLogs() {
        XCTAssertEqual(LogClassifier.category(for: "[TCP] example.com match DomainSuffix using Proxy"), .rule)
        XCTAssertEqual(LogClassifier.category(for: "[TCP] apple.com --> DIRECT"), .direct)
        XCTAssertEqual(LogClassifier.category(for: "proxy provider updated"), .proxy)
        XCTAssertEqual(LogClassifier.category(for: "supercore started"), .system)
    }

    func testSubscriptionInfoParserReadsMetadataURIFragments() {
        let decoded = [
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:1234#%E5%89%A9%E4%BD%99%E6%B5%81%E9%87%8F%EF%BC%9A61.68%20GB",
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:1234#%E8%B7%9D%E7%A6%BB%E4%B8%8B%E6%AC%A1%E9%87%8D%E7%BD%AE%E5%89%A9%E4%BD%99%EF%BC%9A18%20%E5%A4%A9",
            "ss://YWVzLTEyOC1nY206cGFzcw@example.com:1234#%E5%A5%97%E9%A4%90%E5%88%B0%E6%9C%9F%EF%BC%9A2026-06-24"
        ].joined(separator: "\r\n")
        let encoded = Data(decoded.utf8).base64EncodedString()

        let info = SubscriptionInfoParser.parse(text: encoded)

        XCTAssertEqual(info?.remainingTraffic, "61.68 GB")
        XCTAssertEqual(info?.resetInfo, "18 天")
        XCTAssertEqual(info?.expiresAtText, "2026-06-24")
    }

    func testSubscriptionInfoParserReadsUserInfoHeader() {
        let info = SubscriptionInfoParser.parse(
            text: "proxies: []",
            headers: ["subscription-userinfo": "upload=1024; download=2048; total=4096; expire=1782259200"]
        )

        XCTAssertEqual(info?.usedTraffic, "3.0 KB")
        XCTAssertEqual(info?.totalTraffic, "4.0 KB")
        XCTAssertEqual(info?.remainingTraffic, "1.0 KB")
        XCTAssertEqual(info?.expiresAtText, "2026-06-24")
    }
}
