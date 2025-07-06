#!/bin/bash

# Script to build FreeType for iOS as a framework
# Supports both device (arm64) and simulator (x86_64 and arm64)

set -e

SKIP_PREPARE=0
# Parse arguments
for arg in "$@"; do
    if [ "$arg" == "--skip-prepare" ]; then
        SKIP_PREPARE=1
        # Remove the argument from $@
        set -- "${@/"$arg"}"
    fi
done

# Configuration
TARGET_DIR="$1"
FREETYPE_VERSION="$2"

# Convert TARGET_DIR to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"

# Define directories
BUILD_DIR="$TARGET_DIR/build"
DOWNLOAD_DIR="$TARGET_DIR/download"
INSTALL_DIR="$TARGET_DIR/install"
FRAMEWORK_DIR="$INSTALL_DIR/xcframework"

# XCFRAMEWORK Configuration
FRAMEWORK_NAME="FreeType"
FRAMEWORK_CURRENT_VERSION="$FREETYPE_VERSION"

# iOS SDK version
MIN_IOS_VERSION="11.0"

# Architectures
ARCH_DEVICE="arm64"
ARCH_SIMULATOR_INTEL="x86_64"
ARCH_SIMULATOR_ARM="arm64"

function check() {
    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_VERSION>"
        exit 1
    fi

    # Check that FREETYPE_VERSION argument has been passed
    if [ -z "$FREETYPE_VERSION" ]; then
        echo "Error: FREETYPE_VERSION argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_VERSION>"
        exit 1
    fi
}

function prepare() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"

    # Download freetype if not already present
    if [ ! -f "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz" ]; then
        echo "Downloading freetype..."
        curl -L "https://download.savannah.gnu.org/releases/freetype/freetype-$FREETYPE_VERSION.tar.gz" -o "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz"
    fi

    # Extract freetype if not already extracted
    if [ ! -d "$BUILD_DIR/freetype-$FREETYPE_VERSION" ]; then
        echo "Extracting freetype..."
        tar xzf "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    echo "Building FreeType version ${FREETYPE_VERSION} for iOS"

    build_for_architecture() {
        local ARCH=$1
        local PLATFORM=$2
        local SDK=$3
        local BUILD_PATH="${BUILD_DIR}/${ARCH}_${PLATFORM}"
        local INSTALL_PATH="${INSTALL_DIR}/${ARCH}_${PLATFORM}"

        echo "Building for ${ARCH} (${PLATFORM})"

        mkdir -p "${BUILD_PATH}"

        # Get SDK path
        SDK_PATH=$(xcrun --sdk "${SDK}" --show-sdk-path)

        # Configure and build with CMake
        cd "${BUILD_PATH}"

        # CMake toolchain file for iOS
        cat > "${BUILD_PATH}/ios.toolchain.cmake" << EOF
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_ARCHITECTURES ${ARCH})
set(CMAKE_OSX_SYSROOT ${SDK_PATH})
set(CMAKE_OSX_DEPLOYMENT_TARGET ${MIN_IOS_VERSION})
set(CMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH NO)
set(CMAKE_IOS_INSTALL_COMBINED NO)
set(CMAKE_FIND_ROOT_PATH ${SDK_PATH})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS "-arch ${ARCH} -fembed-bitcode")
set(CMAKE_CXX_FLAGS "-arch ${ARCH} -fembed-bitcode")
EOF

        # Run CMake
        cmake "$BUILD_DIR/freetype-${FREETYPE_VERSION}" \
            -DCMAKE_TOOLCHAIN_FILE="${BUILD_PATH}/ios.toolchain.cmake" \
            -DCMAKE_INSTALL_PREFIX="$INSTALL_PATH" \
            -DBUILD_SHARED_LIBS=OFF \
            -DCMAKE_BUILD_TYPE=Release

        # Build
        cmake --build . --config Release
        cmake --install . --config Release
    }

    # Build for device
    build_for_architecture "${ARCH_DEVICE}" "iPhoneOS" "iphoneos"

    # Build for Intel simulator
    build_for_architecture "${ARCH_SIMULATOR_INTEL}" "iPhoneSimulator" "iphonesimulator"

    # Build for Apple Silicon simulator
    build_for_architecture "${ARCH_SIMULATOR_ARM}" "iPhoneSimulator" "iphonesimulator"

    # Verify architectures
    echo "Verifying architectures of built libraries..."
    lipo -info "${INSTALL_DIR}/${ARCH_DEVICE}_iPhoneOS/lib/libfreetype.a"
    lipo -info "${INSTALL_DIR}/${ARCH_SIMULATOR_INTEL}_iPhoneSimulator/lib/libfreetype.a"
    lipo -info "${INSTALL_DIR}/${ARCH_SIMULATOR_ARM}_iPhoneSimulator/lib/libfreetype.a"

    # Create Framework folders
    mkdir -p "${BUILD_DIR}/Headers"
    mkdir -p "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}.xcframework"

    # Copy headers
    cp -R "${INSTALL_DIR}/${ARCH_DEVICE}_iPhoneOS/include/freetype2/ft2build.h" "${BUILD_DIR}/Headers/"
    cp -R "${INSTALL_DIR}/${ARCH_DEVICE}_iPhoneOS/include/freetype2/freetype" "${BUILD_DIR}/Headers/"

    # Create Info.plist
    cat > "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}.xcframework/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>English</string>
  <key>CFBundleExecutable</key>
  <string>${FRAMEWORK_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>org.freetype.${FRAMEWORK_NAME}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${FRAMEWORK_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleShortVersionString</key>
  <string>${FRAMEWORK_CURRENT_VERSION}</string>
  <key>CFBundleSignature</key>
  <string>????</string>
  <key>CFBundleVersion</key>
  <string>${FRAMEWORK_CURRENT_VERSION}</string>
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>iPhoneOS</string>
    <string>iPhoneSimulator</string>
  </array>
  <key>MinimumOSVersion</key>
  <string>${MIN_IOS_VERSION}</string>
  <key>UIDeviceFamily</key>
  <array>
    <integer>1</integer>
    <integer>2</integer>
  </array>
</dict>
</plist>
EOF

    # Create separate libraries for device and simulator
    # First, create a simulator library with both x86_64 and arm64 architectures
    mkdir -p "${BUILD_DIR}/simulator_libs"
    lipo -create \
        "${INSTALL_DIR}/${ARCH_SIMULATOR_INTEL}_iPhoneSimulator/lib/libfreetype.a" \
        "${INSTALL_DIR}/${ARCH_SIMULATOR_ARM}_iPhoneSimulator/lib/libfreetype.a" \
        -output "${BUILD_DIR}/simulator_libs/libfreetype_simulator.a"

    xcrun xcodebuild -create-xcframework \
        -library "$INSTALL_DIR/arm64_iPhoneOS/lib/libfreetype.a" \
        -headers "${BUILD_DIR}/Headers" \
        -library "${BUILD_DIR}/simulator_libs/libfreetype_simulator.a" \
        -headers "${BUILD_DIR}/Headers" \
        -output "$FRAMEWORK_DIR/${FRAMEWORK_NAME}.xcframework"


    echo "Framework successfully created at: ${FRAMEWORK_DIR}"
}


check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
