// swift-tools-version:5.7
import PackageDescription

let package = Package(
  name: "PoDoFo",
  platforms: [
    .iOS(.v16)
  ],
  products: [
    .library(
    name: "PoDoFo",
    targets: ["PoDoFo"]
               ),
  ],
  targets: [
    .binaryTarget(
    name: "PoDoFo",
    path: "./ios-package/PoDoFo.xcframework"
            )
  ]
)
