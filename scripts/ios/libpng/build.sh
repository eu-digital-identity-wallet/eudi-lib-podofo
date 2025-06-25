#!/bin/bash

# Script to build libpng for iOS as unified XCFrameworks
# Supports arm64 for devices, arm64 and x86_64 for simulators
# Creates a single XCFramework for each library with two slices:
# - One for device (arm64)
# - One fat library for simulator (arm64 + x86_64)
# Minimum iOS version: 16.0

set -e

# Configuration
MIN_IOS_VERSION="16.0"
ZLIB_VERSION="1.3.1"
LIBPNG_VERSION="1.6.48"

# Directories
BUILD_DIR="$(pwd)/build"
INSTALL_DIR="$(pwd)/install"
XCFRAMEWORK_DIR="$(pwd)/xcframework"
TEMP_DIR="$(pwd)/temp"
FAT_DIR="$(pwd)/fat"

# Clean up previous builds
rm -rf "$BUILD_DIR" "$INSTALL_DIR" "$XCFRAMEWORK_DIR" "$TEMP_DIR" "$FAT_DIR"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$XCFRAMEWORK_DIR" "$TEMP_DIR" "$FAT_DIR/simulator"

# Download and extract zlib if not already present
if [ ! -d "zlib-${ZLIB_VERSION}" ]; then
    echo "Downloading zlib-${ZLIB_VERSION}..."
    curl -L "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz" -o "zlib-${ZLIB_VERSION}.tar.gz"
    tar -xzf "zlib-${ZLIB_VERSION}.tar.gz"
fi

# Download and extract libpng if not already present
if [ ! -d "libpng-${LIBPNG_VERSION}" ]; then
    echo "Downloading libpng-${LIBPNG_VERSION}..."
    curl -L "https://download.sourceforge.net/libpng/libpng-${LIBPNG_VERSION}.tar.gz" -o "libpng-${LIBPNG_VERSION}.tar.gz"
    tar -xzf "libpng-${LIBPNG_VERSION}.tar.gz"
fi

# Create iOS toolchain file
cat > "$TEMP_DIR/ios.toolchain.cmake" << EOF
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
    
    mkdir -p "$build_dir/zlib" "$build_dir/libpng" "$install_dir"
    
    # Set SDK path based on platform
    if [ "$platform" == "iphoneos" ]; then
        SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
    else
        SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)
    fi
    
    echo "Building for $platform ($arch)"
    
    # Build zlib
    echo "Building zlib for $platform ($arch)"
    cd "$build_dir/zlib"
    
    # Force architecture for x86_64
    if [ "$arch" == "x86_64" ]; then
        export CFLAGS="-arch x86_64"
        export LDFLAGS="-arch x86_64"
    else
        unset CFLAGS
        unset LDFLAGS
    fi
    
    cmake "../../../zlib-${ZLIB_VERSION}" \
        -DCMAKE_TOOLCHAIN_FILE="$TEMP_DIR/ios.toolchain.cmake" \
        -DCMAKE_INSTALL_PREFIX="$install_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DARCH="$arch" \
        -DDEPLOYMENT_TARGET="$MIN_IOS_VERSION" \
        -DSDK_PATH="$SDK_PATH"
    cmake --build . --config Release
    cmake --install . --config Release
    
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
    
    cmake "../../../libpng-${LIBPNG_VERSION}" \
        -DCMAKE_TOOLCHAIN_FILE="$TEMP_DIR/ios.toolchain.cmake" \
        -DCMAKE_INSTALL_PREFIX="$install_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DARCH="$arch" \
        -DDEPLOYMENT_TARGET="$MIN_IOS_VERSION" \
        -DSDK_PATH="$SDK_PATH" \
        -DZLIB_ROOT="$install_dir" \
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
lipo -info "$INSTALL_DIR/iphoneos-arm64/lib/libz.a"
lipo -info "$INSTALL_DIR/iphonesimulator-arm64/lib/libz.a"
lipo -info "$INSTALL_DIR/iphonesimulator-x86_64/lib/libz.a"
lipo -info "$INSTALL_DIR/iphoneos-arm64/lib/libpng16.a"
lipo -info "$INSTALL_DIR/iphonesimulator-arm64/lib/libpng16.a"
lipo -info "$INSTALL_DIR/iphonesimulator-x86_64/lib/libpng16.a"

# Create fat libraries for simulator
echo "Creating fat libraries for simulator..."
mkdir -p "$FAT_DIR/simulator/lib" "$FAT_DIR/simulator/include"

# Create fat library for zlib
lipo -create \
    "$INSTALL_DIR/iphonesimulator-arm64/lib/libz.a" \
    "$INSTALL_DIR/iphonesimulator-x86_64/lib/libz.a" \
    -output "$FAT_DIR/simulator/lib/libz.a"

# Create fat library for libpng
lipo -create \
    "$INSTALL_DIR/iphonesimulator-arm64/lib/libpng16.a" \
    "$INSTALL_DIR/iphonesimulator-x86_64/lib/libpng16.a" \
    -output "$FAT_DIR/simulator/lib/libpng16.a"

# Create separate header directories for zlib and libpng
mkdir -p "$TEMP_DIR/zlib_headers/device" "$TEMP_DIR/zlib_headers/simulator"
mkdir -p "$TEMP_DIR/libpng_headers/device" "$TEMP_DIR/libpng_headers/simulator"

# Copy only zlib headers
echo "Extracting zlib headers..."
cp "$INSTALL_DIR/iphoneos-arm64/include/zconf.h" "$TEMP_DIR/zlib_headers/device/"
cp "$INSTALL_DIR/iphoneos-arm64/include/zlib.h" "$TEMP_DIR/zlib_headers/device/"
cp "$INSTALL_DIR/iphonesimulator-x86_64/include/zconf.h" "$TEMP_DIR/zlib_headers/simulator/"
cp "$INSTALL_DIR/iphonesimulator-x86_64/include/zlib.h" "$TEMP_DIR/zlib_headers/simulator/"

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
lipo -info "$FAT_DIR/simulator/lib/libz.a"
lipo -info "$FAT_DIR/simulator/lib/libpng16.a"

# Create XCFramework for zlib
echo "Creating XCFramework for zlib..."
rm -rf "$XCFRAMEWORK_DIR/zlib.xcframework"

xcrun xcodebuild -create-xcframework \
    -library "$INSTALL_DIR/iphoneos-arm64/lib/libz.a" \
    -headers "$TEMP_DIR/zlib_headers/device" \
    -library "$FAT_DIR/simulator/lib/libz.a" \
    -headers "$TEMP_DIR/zlib_headers/simulator" \
    -output "$XCFRAMEWORK_DIR/zlib.xcframework"

# Create XCFramework for libpng
echo "Creating XCFramework for libpng..."
rm -rf "$XCFRAMEWORK_DIR/libpng.xcframework"

xcrun xcodebuild -create-xcframework \
    -library "$INSTALL_DIR/iphoneos-arm64/lib/libpng16.a" \
    -headers "$TEMP_DIR/libpng_headers/device" \
    -library "$FAT_DIR/simulator/lib/libpng16.a" \
    -headers "$TEMP_DIR/libpng_headers/simulator" \
    -output "$XCFRAMEWORK_DIR/libpng.xcframework"

# Verify the XCFramework structure
echo "XCFramework structure for zlib:"
find "$XCFRAMEWORK_DIR/zlib.xcframework" -type d -maxdepth 2

echo "XCFramework structure for libpng:"
find "$XCFRAMEWORK_DIR/libpng.xcframework" -type d -maxdepth 2

echo "Fixed XCFrameworks created successfully at ${XCFRAMEWORK_DIR}"
echo "Each XCFramework contains:"
echo "  - Device slice (arm64)"
echo "  - Simulator slice (fat library with arm64 and x86_64)"
echo "  - Only its own headers (no duplicate headers between frameworks)" 