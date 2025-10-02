// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "secrypt",
  platforms: [.macOS(.v13)],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    .package(url: "https://github.com/valpackett/SwiftCBOR", from: "0.5.0"),
  ],
  targets: [
    .executableTarget(
      name: "secrypt",
      dependencies: [
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
        .product(name: "SwiftCBOR", package: "SwiftCBOR"),
      ],
      path: "Sources"),
  ]
)