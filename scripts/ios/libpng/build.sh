#!/bin/bash

# Script to build libpng for iOS as unified XCFrameworks
# Supports arm64 for devices, arm64 and x86_64 for simulators
# Creates a single XCFramework for each library with two slices:
# - One for device (arm64)
# - One fat library for simulator (arm64 + x86_64)
# Minimum iOS version: 14.0

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
LIBPNG_VERSION="$2"

# Convert TARGET_DIR to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"

# Define directories
BUILD_DIR="$TARGET_DIR/build"
DOWNLOAD_DIR="$TARGET_DIR/download"
INSTALL_DIR="$TARGET_DIR/install"
XCFRAMEWORK_DIR="$INSTALL_DIR/xcframework"
TEMP_DIR="$TARGET_DIR/temp"
FAT_DIR="$TARGET_DIR/fat"

# Configuration
MIN_IOS_VERSION="14.0"

# Source files directory
SRC_DIR=$(pwd)

function check() {
    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <LIBPNG_VERSION>"
        exit 1
    fi

    # Check that LIBPNG_VERSION argument has been passed
    if [ -z "$LIBPNG_VERSION" ]; then
        echo "Error: LIBPNG_VERSION argument not provided."
        echo "Usage: $0 <TARGET_DIR> <LIBPNG_VERSION>"
        exit 1
    fi
}

function prepare() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"

    # Download freetype if not already present
    if [ ! -f "$DOWNLOAD_DIR/libpng-${LIBPNG_VERSION}.tar.gz" ]; then
        echo "Downloading libpng..."
        curl -L "https://download.sourceforge.net/libpng/libpng-$LIBPNG_VERSION.tar.gz" -o "$DOWNLOAD_DIR/libpng-$LIBPNG_VERSION.tar.gz"
    fi

    # Extract libpng if not already extracted
    if [ ! -d "$BUILD_DIR/libpng-$LIBPNG_VERSION" ]; then
        echo "Extracting libpng..."
        tar xzf "$DOWNLOAD_DIR/libpng-$LIBPNG_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    # Create iOS toolchain file
    cat > "$BUILD_DIR/ios.toolchain.cmake" << EOF
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_ARCHITECTURES \${ARCH})
set(CMAKE_OSX_DEPLOYMENT_TARGET \${DEPLOYMENT_TARGET})
set(CMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH NO)
set(CMAKE_IOS_INSTALL_COMBINED NO)
set(CMAKE_SYSTEM_PROCESSOR \${ARCH})
set(CMAKE_OSX_SYSROOT \${SDK_PATH})
set(CMAKE_FIND_ROOT_PATH \${SDK_PATH})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF

    # Function to build for a specific platform and architecture
    build_arch() {
        local platform=$1
        local arch=$2
        local build_dir="${BUILD_DIR}/${platform}-${arch}"
        local install_dir="${INSTALL_DIR}/${platform}-${arch}"

        mkdir -p "$build_dir/libpng" "$install_dir"

        # Set SDK path based on platform
        if [ "$platform" == "iphoneos" ]; then
            SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
        else
            SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)
        fi

        echo "Building for $platform ($arch)"

        # Build libpng
        echo "Building libpng for $platform ($arch)"
        cd "$build_dir/libpng"

        # Force architecture for x86_64
        if [ "$arch" == "x86_64" ]; then
            export CFLAGS="-arch x86_64"
            export LDFLAGS="-arch x86_64"
        else
            unset CFLAGS
            unset LDFLAGS
        fi

        cmake "$BUILD_DIR/libpng-${LIBPNG_VERSION}" \
            -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/ios.toolchain.cmake" \
            -DCMAKE_INSTALL_PREFIX="$install_dir" \
            -DCMAKE_BUILD_TYPE=Release \
            -DARCH="$arch" \
            -DDEPLOYMENT_TARGET="$MIN_IOS_VERSION" \
            -DSDK_PATH="$SDK_PATH" \
            -DPNG_SHARED=OFF \
            -DPNG_TESTS=OFF
        cmake --build . --config Release
        cmake --install . --config Release
    }

    # Build for device (arm64)
    build_arch "iphoneos" "arm64"

    # Build for simulator (arm64)
    build_arch "iphonesimulator" "arm64"

    # Build for simulator (x86_64)
    build_arch "iphonesimulator" "x86_64"

    # Verify architectures
    echo "Verifying architectures..."
    lipo -info "$INSTALL_DIR/iphoneos-arm64/lib/libpng16.a"
    lipo -info "$INSTALL_DIR/iphonesimulator-arm64/lib/libpng16.a"
    lipo -info "$INSTALL_DIR/iphonesimulator-x86_64/lib/libpng16.a"

    # Create fat libraries for simulator
    echo "Creating fat libraries for simulator..."
    mkdir -p "$FAT_DIR/simulator/lib" "$FAT_DIR/simulator/include"

    # Create fat library for libpng
    lipo -create \
        "$INSTALL_DIR/iphonesimulator-arm64/lib/libpng16.a" \
        "$INSTALL_DIR/iphonesimulator-x86_64/lib/libpng16.a" \
        -output "$FAT_DIR/simulator/lib/libpng16.a"

    # Create separate header directories for zlib and libpng
    mkdir -p "$TEMP_DIR/libpng_headers/device" "$TEMP_DIR/libpng_headers/simulator"

    # Copy only libpng headers
    echo "Extracting libpng headers..."
    mkdir -p "$TEMP_DIR/libpng_headers/device/libpng16" "$TEMP_DIR/libpng_headers/simulator/libpng16"
    cp "$INSTALL_DIR/iphoneos-arm64/include/png.h" "$TEMP_DIR/libpng_headers/device/"
    cp "$INSTALL_DIR/iphoneos-arm64/include/pngconf.h" "$TEMP_DIR/libpng_headers/device/"
    cp "$INSTALL_DIR/iphoneos-arm64/include/pnglibconf.h" "$TEMP_DIR/libpng_headers/device/"
    cp "$INSTALL_DIR/iphoneos-arm64/include/libpng16/"* "$TEMP_DIR/libpng_headers/device/libpng16/"

    cp "$INSTALL_DIR/iphonesimulator-x86_64/include/png.h" "$TEMP_DIR/libpng_headers/simulator/"
    cp "$INSTALL_DIR/iphonesimulator-x86_64/include/pngconf.h" "$TEMP_DIR/libpng_headers/simulator/"
    cp "$INSTALL_DIR/iphonesimulator-x86_64/include/pnglibconf.h" "$TEMP_DIR/libpng_headers/simulator/"
    cp "$INSTALL_DIR/iphonesimulator-x86_64/include/libpng16/"* "$TEMP_DIR/libpng_headers/simulator/libpng16/"

    # Verify fat libraries
    echo "Verifying fat libraries..."
    lipo -info "$FAT_DIR/simulator/lib/libpng16.a"

    # Create XCFramework for libpng
    echo "Creating XCFramework for libpng..."
    rm -rf "$XCFRAMEWORK_DIR/libpng.xcframework"

    xcrun xcodebuild -create-xcframework \
        -library "$INSTALL_DIR/iphoneos-arm64/lib/libpng16.a" \
        -headers "$TEMP_DIR/libpng_headers/device" \
        -library "$FAT_DIR/simulator/lib/libpng16.a" \
        -headers "$TEMP_DIR/libpng_headers/simulator" \
        -output "$XCFRAMEWORK_DIR/libpng.xcframework"

    echo "XCFramework structure for libpng:"
    find "$XCFRAMEWORK_DIR/libpng.xcframework" -type d -maxdepth 2

    echo "Fixed XCFrameworks created successfully at ${XCFRAMEWORK_DIR}"
    echo "Each XCFramework contains:"
    echo "  - Device slice (arm64)"
    echo "  - Simulator slice (fat library with arm64 and x86_64)"
    echo "  - Only its own headers (no duplicate headers between frameworks)"
}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
