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
            private var _queuedResponses: [(Int, Data)] = []

            func reset() {
                lock.lock()
                defer { lock.unlock() }
                _lastRequest = nil
                _lastBody = nil
                _responseBody = Data("{\"ok\":true,\"group\":\"\",\"results\":[]}".utf8)
                _responseStatusCode = 200
                _queuedResponses = []
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

            func enqueueResponse(statusCode: Int, body: Data) {
                lock.lock()
                defer { lock.unlock() }
                _queuedResponses.append((statusCode, body))
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

            func nextResponse() -> (Int, Data) {
                lock.lock()
                defer { lock.unlock() }
                if !_queuedResponses.isEmpty {
                    return _queuedResponses.removeFirst()
                }
                return (_responseStatusCode, _responseBody)
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

        static func enqueueResponse(statusCode: Int = 200, body: Data) {
            captureState.enqueueResponse(statusCode: statusCode, body: body)
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
            let (statusCode, responseBody) = Self.captureState.nextResponse()
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: statusCode,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )
            if let response {
                client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            client.urlProtocol(self, didLoad: responseBody)
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

    func testProbeWaitsForAcceptedTaskResult() async throws {
        let client = SupercoreAPIClient(baseURL: URL(string: "http://127.0.0.1:9197")!)
        SupercoreProbeGroupCaptureProtocol.enqueueResponse(
            statusCode: 202,
            body: Data(
                """
                {"task_id":"task-123","kind":"probe_outbounds","status":"queued"}
                """.utf8
            )
        )
        SupercoreProbeGroupCaptureProtocol.enqueueResponse(
            body: Data(
                """
                {
                  "id":"task-123",
                  "kind":"probe_outbounds",
                  "status":"succeeded",
                  "current":1,
                  "total":1,
                  "message":"completed",
                  "result":{
                    "results":[
                      {"name":"HK-01","kind":"ss","success":true,"latency_ms":42,"error":null}
                    ],
                    "failure_summary":{}
                  },
                  "error":null
                }
                """.utf8
            )
        )

        let response = try await client.probeOutboundsResponse(
            timeoutMilliseconds: 500,
            url: DelayPolicy.probeURL,
            concurrency: 1,
            names: ["HK-01"]
        )

        XCTAssertEqual(response.results.first?.name, "HK-01")
        XCTAssertEqual(response.results.first?.latencyMs, 42)
        XCTAssertEqual(SupercoreProbeGroupCaptureProtocol.lastRequest?.url?.path, "/v1/tasks/task-123")
    }

    func testCancellingProbeSendsCoreTaskCancellation() async throws {
        let client = SupercoreAPIClient(baseURL: URL(string: "http://127.0.0.1:9197")!)
        SupercoreProbeGroupCaptureProtocol.enqueueResponse(
            statusCode: 202,
            body: Data(
                """
                {"task_id":"task-cancel","kind":"probe_outbounds","status":"queued"}
                """.utf8
            )
        )
        SupercoreProbeGroupCaptureProtocol.enqueueResponse(
            body: Data(
                """
                {
                  "id":"task-cancel",
                  "kind":"probe_outbounds",
                  "status":"running",
                  "current":0,
                  "total":1,
                  "message":"running",
                  "result":null,
                  "error":null
                }
                """.utf8
            )
        )
        SupercoreProbeGroupCaptureProtocol.responseBody = Data("{\"ok\":true}".utf8)

        let probe = Task {
            try await client.probeOutboundsResponse(
                timeoutMilliseconds: 500,
                url: DelayPolicy.probeURL,
                concurrency: 1,
                names: ["HK-01"]
            )
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        probe.cancel()

        do {
            _ = try await probe.value
            XCTFail("cancelled probe should throw")
        } catch is CancellationError {
            XCTAssertEqual(
                SupercoreProbeGroupCaptureProtocol.lastRequest?.url?.path,
                "/v1/tasks/task-cancel/cancel"
            )
        }
    }

    func testSSEParserPreservesEventIDNameAndMultilineData() throws {
        var parser = SupercoreSSEParser()
        XCTAssertNil(parser.consume(line: ": keepalive"))
        XCTAssertNil(parser.consume(line: "id: event-123"))
        XCTAssertNil(parser.consume(line: "event: traffic_sample"))
        XCTAssertNil(parser.consume(line: "data: {\"upload_total\":64,"))
        XCTAssertNil(parser.consume(line: "data: \"download_total\":128}"))
        let event = try XCTUnwrap(parser.consume(line: ""))

        XCTAssertEqual(event.id, "event-123")
        XCTAssertEqual(event.name, "traffic_sample")
        XCTAssertEqual(
            String(data: event.data, encoding: .utf8),
            "{\"upload_total\":64,\n\"download_total\":128}"
        )
    }

    func testEventStreamConnectsParsesEventAndSendsLastEventID() async throws {
        let client = SupercoreAPIClient(baseURL: URL(string: "http://127.0.0.1:9197")!)
        SupercoreProbeGroupCaptureProtocol.responseBody = Data(
            """
            id: event-456
            event: log_appended
            data: {"schema_version":1,"id":"event-456","event":"log_appended","timestamp":"2026-07-17T00:00:00Z","data":{"time":"2026-07-17T00:00:00Z","level":"info","message":"hello"}}

            """.utf8
        )

        var iterator = client.eventStream(lastEventID: "event-previous").makeAsyncIterator()
        let connected = try await iterator.next()
        XCTAssertEqual(connected, .connected)
        let event = try await iterator.next()
        XCTAssertEqual(event?.id, "event-456")
        XCTAssertEqual(event?.name, "log_appended")
        XCTAssertEqual(
            SupercoreProbeGroupCaptureProtocol.lastRequest?.value(forHTTPHeaderField: "Last-Event-ID"),
            "event-previous"
        )
        XCTAssertEqual(SupercoreProbeGroupCaptureProtocol.lastRequest?.url?.path, "/v1/events")
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
        XCTAssertEqual(request.timeoutInterval, 10)
        XCTAssertGreaterThanOrEqual(
            ProbeTimeoutCalculator.requestTimeout(
                timeoutMilliseconds: 500,
                concurrency: nil,
                names: nil
            ),
            60
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
