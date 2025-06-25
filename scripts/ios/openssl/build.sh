#!/bin/bash

# Script to download and build OpenSSL for iOS
# Creates frameworks for both device and simulator
# FIXED VERSION - Properly separates device and simulator builds

set -e

# Configuration
OPENSSL_VERSION="3.2.1"  # Latest stable version
MIN_IOS_VERSION="12.0"

# Directories
CURRENT_DIR=$(pwd)
DOWNLOAD_DIR="${CURRENT_DIR}/downloads"
BUILD_DIR="${CURRENT_DIR}/build"
FRAMEWORK_DIR="${CURRENT_DIR}/frameworks"

# Create necessary directories
mkdir -p "${DOWNLOAD_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${FRAMEWORK_DIR}"

# Download OpenSSL if not already downloaded
if [ ! -f "${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    curl -L "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -o "${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
fi

# Extract OpenSSL
if [ ! -d "${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}" ]; then
    echo "Extracting OpenSSL..."
    tar -xzf "${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz" -C "${DOWNLOAD_DIR}"
fi

# Get Xcode paths
DEVELOPER=$(xcode-select -print-path)
IPHONEOS_SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
IPHONESIMULATOR_SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)

# Function to build OpenSSL for a specific architecture
build_for_arch() {
    ARCH=$1
    PLATFORM=$2
    SDK_PATH=$3
    BUILD_TYPE=$4  # "device" or "simulator"
    
    echo "Building OpenSSL for ${ARCH} (${PLATFORM}) - ${BUILD_TYPE}..."
    
    # Prepare build directory - use BUILD_TYPE to make directories unique
    ARCH_BUILD_DIR="${BUILD_DIR}/${ARCH}-${BUILD_TYPE}"
    mkdir -p "${ARCH_BUILD_DIR}"
    
    # Navigate to source directory
    cd "${DOWNLOAD_DIR}/openssl-${OPENSSL_VERSION}"
    
    # Clean previous builds
    make clean || true
    
    # Set up compiler flags
    export CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
    export CROSS_SDK=$(basename ${SDK_PATH})
    export CC="$(xcrun -sdk $(echo ${PLATFORM} | tr '[:upper:]' '[:lower:]') -find clang) -arch ${ARCH}"
    
    # Set up OpenSSL configure options
    if [[ "${ARCH}" == "x86_64" || "${ARCH}" == "arm64" ]]; then
        if [[ "${PLATFORM}" == "iPhoneSimulator" ]]; then
            # For simulator
            ./Configure darwin64-${ARCH}-cc no-asm no-shared no-async \
                --prefix="${ARCH_BUILD_DIR}" \
                --openssldir="${ARCH_BUILD_DIR}" \
                -isysroot "${SDK_PATH}" \
                -mios-simulator-version-min=${MIN_IOS_VERSION}
        else
            # For device
            ./Configure darwin64-${ARCH}-cc no-asm no-shared no-async \
                --prefix="${ARCH_BUILD_DIR}" \
                --openssldir="${ARCH_BUILD_DIR}" \
                -isysroot "${SDK_PATH}" \
                -mios-version-min=${MIN_IOS_VERSION}
        fi
    else
        echo "Unsupported architecture: ${ARCH}"
        exit 1
    fi
    
    # Build
    make -j$(sysctl -n hw.ncpu) build_libs
    make install_dev
    
    cd "${CURRENT_DIR}"
}

# Clear previous build directories
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Build for iOS device (arm64)
build_for_arch "arm64" "iPhoneOS" "${IPHONEOS_SDK_PATH}" "device"

# Build for iOS simulator (x86_64 and arm64)
build_for_arch "x86_64" "iPhoneSimulator" "${IPHONESIMULATOR_SDK_PATH}" "simulator-x86_64"
build_for_arch "arm64" "iPhoneSimulator" "${IPHONESIMULATOR_SDK_PATH}" "simulator-arm64"

# Create fat library for simulator
echo "Creating fat libraries for simulator..."
mkdir -p "${BUILD_DIR}/simulator/lib"
lipo -create "${BUILD_DIR}/x86_64-simulator-x86_64/lib/libssl.a" "${BUILD_DIR}/arm64-simulator-arm64/lib/libssl.a" -output "${BUILD_DIR}/simulator/lib/libssl.a"
lipo -create "${BUILD_DIR}/x86_64-simulator-x86_64/lib/libcrypto.a" "${BUILD_DIR}/arm64-simulator-arm64/lib/libcrypto.a" -output "${BUILD_DIR}/simulator/lib/libcrypto.a"

# Create XCFrameworks
echo "Creating XCFrameworks..."

# Clean existing frameworks
rm -rf "${FRAMEWORK_DIR}/SSL.xcframework"
rm -rf "${FRAMEWORK_DIR}/Crypto.xcframework"

# Create SSL.xcframework structure
mkdir -p "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64"
mkdir -p "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64_x86_64-simulator"

# Copy SSL libraries
cp "${BUILD_DIR}/arm64-device/lib/libssl.a" "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64/"
cp "${BUILD_DIR}/simulator/lib/libssl.a" "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64_x86_64-simulator/"

# Create Crypto.xcframework structure
mkdir -p "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64"
mkdir -p "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64_x86_64-simulator"

# Copy Crypto libraries
cp "${BUILD_DIR}/arm64-device/lib/libcrypto.a" "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64/"
cp "${BUILD_DIR}/simulator/lib/libcrypto.a" "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64_x86_64-simulator/"

# Copy headers
mkdir -p "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64/Headers"
mkdir -p "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64_x86_64-simulator/Headers"
mkdir -p "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64/Headers"
mkdir -p "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64_x86_64-simulator/Headers"

# Copy DEVICE headers - not simulator headers
cp -R "${BUILD_DIR}/arm64-device/include/openssl" "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64/Headers/"
cp -R "${BUILD_DIR}/arm64-device/include/openssl" "${FRAMEWORK_DIR}/SSL.xcframework/ios-arm64_x86_64-simulator/Headers/"
cp -R "${BUILD_DIR}/arm64-device/include/openssl" "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64/Headers/"
cp -R "${BUILD_DIR}/arm64-device/include/openssl" "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64_x86_64-simulator/Headers/"

# Create Info.plist files for XCFrameworks
cat > "${FRAMEWORK_DIR}/SSL.xcframework/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64</string>
            <key>LibraryPath</key>
            <string>libssl.a</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-simulator</string>
            <key>LibraryPath</key>
            <string>libssl.a</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
            <key>SupportedPlatformVariant</key>
            <string>simulator</string>
        </dict>
    </array>
    <key>CFBundlePackageType</key>
    <string>XFWK</string>
    <key>XCFrameworkFormatVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

cat > "${FRAMEWORK_DIR}/Crypto.xcframework/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64</string>
            <key>LibraryPath</key>
            <string>libcrypto.a</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-simulator</string>
            <key>LibraryPath</key>
            <string>libcrypto.a</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
            <key>SupportedPlatformVariant</key>
            <string>simulator</string>
        </dict>
    </array>
    <key>CFBundlePackageType</key>
    <string>XFWK</string>
    <key>XCFrameworkFormatVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

echo "Successfully created XCFrameworks:"
echo "  - ${FRAMEWORK_DIR}/SSL.xcframework"
echo "  - ${FRAMEWORK_DIR}/Crypto.xcframework"
echo ""
echo "Verifying architecture of built libraries:"
echo "iOS Device (arm64):"
lipo -info "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64/libcrypto.a"
echo ""
echo "iOS Simulator (arm64, x86_64):"
lipo -info "${FRAMEWORK_DIR}/Crypto.xcframework/ios-arm64_x86_64-simulator/libcrypto.a"
echo ""
echo "Build complete!" 