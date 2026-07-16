import Foundation
import XCTest
@testable import YueqiuElevatorSupercore

final class SupercoreAPIClientTests: XCTestCase {
    final class SupercoreProbeGroupCaptureProtocol: URLProtocol {
        private final class State: @unchecked Sendable {
            private let lock = NSLock()
            private var _lastRequest: URLRequest?
            private var _lastBody: Data?
            private var _responseBody = Data("{\"ok\":true,\"group\":\"\",\"results\":[]}".utf8)
            private var _responseStatusCode = 200

            func reset() {
                lock.lock()
                defer { lock.unlock() }
                _lastRequest = nil
                _lastBody = nil
                _responseBody = Data("{\"ok\":true,\"group\":\"\",\"results\":[]}".utf8)
                _responseStatusCode = 200
            }

            func setLastRequest(_ request: URLRequest?, body: Data?) {
                lock.lock()
                defer { lock.unlock() }
                _lastRequest = request
                _lastBody = body
            }

            func setResponseBody(_ responseBody: Data) {
                lock.lock()
                defer { lock.unlock() }
                _responseBody = responseBody
            }

            func setResponseStatusCode(_ statusCode: Int) {
                lock.lock()
                defer { lock.unlock() }
                _responseStatusCode = statusCode
            }

            func lastRequest() -> URLRequest? {
                lock.lock()
                defer { lock.unlock() }
                return _lastRequest
            }

            func lastBody() -> Data? {
                lock.lock()
                defer { lock.unlock() }
                return _lastBody
            }

            func responseBody() -> Data {
                lock.lock()
                defer { lock.unlock() }
                return _responseBody
            }

            func responseStatusCode() -> Int {
                lock.lock()
                defer { lock.unlock() }
                return _responseStatusCode
            }
        }

        private static let captureState = State()

        static var lastRequest: URLRequest? {
            captureState.lastRequest()
        }

        static var lastBody: Data? {
            captureState.lastBody()
        }

        static var responseBody: Data {
            get { captureState.responseBody() }
            set { captureState.setResponseBody(newValue) }
        }

        static var responseStatusCode: Int {
            get { captureState.responseStatusCode() }
            set { captureState.setResponseStatusCode(newValue) }
        }

        static func reset() {
            captureState.reset()
        }

        override class func canInit(with request: URLRequest) -> Bool {
            true
        }

        override class func canonicalRequest(for request: URLRequest) -> URLRequest {
            request
        }

        override func startLoading() {
            guard let client else { return }
            let requestBody = captureBody(from: request)
            Self.captureState.setLastRequest(request, body: requestBody)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: Self.responseStatusCode,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )
            if let response {
                client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            client.urlProtocol(self, didLoad: Self.responseBody)
            client.urlProtocolDidFinishLoading(self)
        }

        private func captureBody(from request: URLRequest) -> Data? {
            if let body = request.httpBody {
                return body
            }
            guard let stream = request.httpBodyStream else {
                return nil
            }
            stream.open()
            defer { stream.close() }

            var output = Data()
            var buffer = [UInt8](repeating: 0, count: 1024)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                guard count > 0 else { break }
                output.append(contentsOf: buffer[0..<count])
            }
            return output.isEmpty ? nil : output
        }

        override func stopLoading() {}
    }

    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(SupercoreProbeGroupCaptureProtocol.self)
        SupercoreProbeGroupCaptureProtocol.reset()
    }

    override func tearDown() {
        URLProtocol.unregisterClass(SupercoreProbeGroupCaptureProtocol.self)
        super.tearDown()
    }

    func testProbeGroupUsesBodyEndpointAndPreservesSpecialCharacters() async throws {
        let groupName = "节点选择/香港"
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)

        _ = try await client.probeGroup(name: groupName, timeoutMilliseconds: 500, url: DelayPolicy.probeURL)

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        XCTAssertEqual(request.url?.path, "/v1/probes/group")

        let body = try XCTUnwrap(SupercoreProbeGroupCaptureProtocol.lastBody)
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any],
            "probe group request body should be JSON"
        )
        XCTAssertEqual(json["group"] as? String, groupName)
        XCTAssertNil(json["names"])
    }

    func testAuthenticatedRequestIncludesBearerToken() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        client.setControlToken("0123456789abcdef0123456789abcdef")
        SupercoreProbeGroupCaptureProtocol.responseBody = Data("{\"ok\":true}".utf8)

        try await client.useOutbound(name: "HK-01")

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        XCTAssertEqual(request.url?.path, "/v1/outbounds/use")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Authorization"),
            "Bearer 0123456789abcdef0123456789abcdef"
        )
    }

    func testStructuredAPIErrorUsesStableCodeAndTrace() async throws {
        let client = SupercoreAPIClient(baseURL: URL(string: "http://127.0.0.1:9197")!)
        client.setControlToken("0123456789abcdef0123456789abcdef")
        SupercoreProbeGroupCaptureProtocol.responseStatusCode = 401
        SupercoreProbeGroupCaptureProtocol.responseBody = Data(
            """
            {
              "code": "control_auth_invalid",
              "kind": "authentication",
              "message": "a valid bearer token is required",
              "retryable": false,
              "trace_id": "trace-123",
              "details": {}
            }
            """.utf8
        )

        do {
            try await client.useOutbound(name: "HK-01")
            XCTFail("request should fail")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("control_auth_invalid"))
            XCTAssertTrue(error.localizedDescription.contains("trace-123"))
        }
    }

    func testProbeGroupWithSlashInNamePreservesRawGroupInBody() async throws {
        let groupName = "A/B/香港"
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)

        _ = try await client.probeGroup(name: groupName)

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        let body = try XCTUnwrap(SupercoreProbeGroupCaptureProtocol.lastBody)
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any],
            "probe group request body should be JSON"
        )
        XCTAssertEqual(request.url?.path, "/v1/probes/group")
        XCTAssertEqual(json["group"] as? String, groupName)
        XCTAssertNil(json["names"])
        XCTAssertNil(request.url?.query)
    }

    func testProbeGroupBodyContainsTimeoutAndConcurrency() async throws {
        let groupName = "emoji-🚀"
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        SupercoreProbeGroupCaptureProtocol.responseBody = Data(
            "{\"ok\":true,\"group\":\"emoji-🚀\",\"results\":[]}".utf8
        )

        _ = try await client.probeGroup(name: groupName, timeoutMilliseconds: 1200, url: "http://127.0.0.1", concurrency: 20)

        _ = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        let body = try XCTUnwrap(SupercoreProbeGroupCaptureProtocol.lastBody)
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any],
            "probe group request body should be JSON"
        )
        XCTAssertEqual(json["timeout_ms"] as? Int, 1200)
        XCTAssertEqual(json["concurrency"] as? Int, 20)
    }

    func testProbeGroupResponseIncludesFailureSummary() async throws {
        let groupName = "A/B/香港"
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        SupercoreProbeGroupCaptureProtocol.responseBody = Data(
            """
            {
              "ok": true,
              "group": "\(groupName)",
              "results":[
                {"name":"HK-01","kind":"ss","success":false,"latency_ms":0,"failure_kind":"timeout","error":"timeout"},
                {"name":"HK-02","kind":"vmess","success":false,"latency_ms":0,"failure_kind":"protocol_unsupported","error":"not implemented"},
                {"name":"HK-03","kind":"trojan","success":true,"latency_ms":80,"error":null}
              ],
              "failure_summary":{"timeout":1,"protocol_unsupported":1}
            }
            """.utf8
        )

        let response = try await client.probeGroupResponse(
            name: groupName,
            timeoutMilliseconds: 500,
            url: DelayPolicy.probeURL,
            concurrency: 20
        )
        XCTAssertEqual(response.group, groupName)
        XCTAssertEqual(response.ok, true)
        XCTAssertEqual(response.results.count, 3)
        XCTAssertEqual(response.failureSummary?["timeout"], 1)
        XCTAssertEqual(response.failureSummary?["protocol_unsupported"], 1)
    }

    func testProbeOutboundsUsesCalculatedTimeoutForBatchCount() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        let names = Array(repeating: "node", count: 131)

        _ = try await client.probeOutbounds(timeoutMilliseconds: 500, url: DelayPolicy.probeURL, concurrency: 50, names: names)

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        XCTAssertEqual(request.url?.path, "/v1/probes")
        XCTAssertEqual(
            request.timeoutInterval,
            ProbeTimeoutCalculator.requestTimeout(timeoutMilliseconds: 500, concurrency: 50, names: names)
        )
    }

    func testProbeOutboundsUsesCalculatedTimeoutWithoutNames() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)

        _ = try await client.probeOutbounds(timeoutMilliseconds: 500, url: DelayPolicy.probeURL, concurrency: nil, names: nil)

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        XCTAssertEqual(request.url?.path, "/v1/probes")
        XCTAssertEqual(
            request.timeoutInterval,
            ProbeTimeoutCalculator.requestTimeout(timeoutMilliseconds: 500, concurrency: nil, names: nil)
        )
    }

    func testProbeOutboundsUsesDefaultConcurrencyTimeoutWhenNil() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        let names = Array(repeating: "node", count: 131)

        _ = try await client.probeOutbounds(timeoutMilliseconds: 500, url: DelayPolicy.probeURL, concurrency: nil, names: names)

        let request = try XCTUnwrap(
            SupercoreProbeGroupCaptureProtocol.lastRequest,
            "supercore API client should issue one request"
        )
        XCTAssertEqual(
            request.timeoutInterval,
            ProbeTimeoutCalculator.requestTimeout(timeoutMilliseconds: 500, concurrency: nil, names: names)
        )
    }

    func testProbeOutboundsBodyContainsRequestedNodeNames() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        let names = ["nodeA", "nodeB", "nodeC"]

        _ = try await client.probeOutbounds(timeoutMilliseconds: 500, url: DelayPolicy.probeURL, concurrency: 20, names: names)

        let body = try XCTUnwrap(SupercoreProbeGroupCaptureProtocol.lastBody)
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: body) as? [String: Any],
            "probe outbounds request body should be JSON"
        )
        XCTAssertEqual(json["timeout_ms"] as? Int, 500)
        XCTAssertEqual(json["concurrency"] as? Int, 20)
        XCTAssertEqual(json["url"] as? String, DelayPolicy.probeURL)
        XCTAssertEqual(json["names"] as? [String], names)
    }

    func testProbeOutboundsResponseIncludesFailureSummary() async throws {
        let baseURL = URL(string: "http://127.0.0.1:9197")!
        let client = SupercoreAPIClient(baseURL: baseURL)
        SupercoreProbeGroupCaptureProtocol.responseBody = Data(
            """
            {
              "results":[
                {"name":"HK-01","kind":"ss","success":false,"latency_ms":0,"failure_kind":"timeout","error":"timeout"},
                {"name":"HK-02","kind":"vmess","success":false,"latency_ms":0,"failure_kind":"protocol_unsupported","error":"not implemented"},
                {"name":"HK-03","kind":"trojan","success":true,"latency_ms":120,"error":null}
              ],
              "failure_summary":{"timeout":1,"protocol_unsupported":1}
            }
            """.utf8
        )

        let response = try await client.probeOutboundsResponse(
            timeoutMilliseconds: 500,
            url: DelayPolicy.probeURL,
            concurrency: 20,
            names: ["HK-01", "HK-02", "HK-03"]
        )
        XCTAssertEqual(response.results.count, 3)
        XCTAssertEqual(response.failureSummary?["timeout"], 1)
        XCTAssertEqual(response.failureSummary?["protocol_unsupported"], 1)
    }
}
