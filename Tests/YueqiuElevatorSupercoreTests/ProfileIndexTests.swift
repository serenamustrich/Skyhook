import XCTest
@testable import YueqiuElevatorSupercore

final class ProfileIndexTests: XCTestCase {
    func testFirstImportedProfileBecomesActive() {
        let imported = makeProfile(id: "new")

        let index = ProfileIndex(activeProfileID: nil, profiles: [])
            .appendingImportedProfile(imported)

        XCTAssertEqual(index.activeProfileID, "new")
        XCTAssertEqual(index.profiles.map(\.id), ["new"])
    }

    func testImportDoesNotReplaceExistingActiveProfile() {
        let current = makeProfile(id: "current")
        let imported = makeProfile(id: "new")

        let index = ProfileIndex(activeProfileID: "current", profiles: [current])
            .appendingImportedProfile(imported)

        XCTAssertEqual(index.activeProfileID, "current")
        XCTAssertEqual(index.profiles.map(\.id), ["current", "new"])
    }

    private func makeProfile(id: String) -> SubscriptionProfile {
        SubscriptionProfile(
            id: id,
            name: id,
            maskedURL: "https://example.com/\(id)",
            importedAt: Date(timeIntervalSince1970: 0),
            updatedAt: Date(timeIntervalSince1970: 0),
            selectedNodes: [:],
            planInfo: nil
        )
    }
}
