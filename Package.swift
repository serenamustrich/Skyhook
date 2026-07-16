// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "YueqiuElevatorSupercore",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "YueqiuElevatorSupercore", targets: ["YueqiuElevatorSupercore"])
    ],
    targets: [
        .executableTarget(
            name: "YueqiuElevatorSupercore",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "YueqiuElevatorSupercoreTests",
            dependencies: ["YueqiuElevatorSupercore"]
        )
    ]
)
