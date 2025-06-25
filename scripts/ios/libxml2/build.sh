#!/bin/bash

# Script to build libxml2 for iOS devices and simulators as frameworks
# Based on the latest stable version of libxml2

set -e

# Configuration
LIBXML2_VERSION="2.11.5"
LIBXML2_DOWNLOAD_URL="https://download.gnome.org/sources/libxml2/2.11/libxml2-${LIBXML2_VERSION}.tar.xz"
DEVELOPER=$(xcode-select -print-path)
IPHONEOS_SDK_VERSION=$(xcrun -sdk iphoneos --show-sdk-version)
IPHONESIMULATOR_SDK_VERSION=$(xcrun -sdk iphonesimulator --show-sdk-version)
IPHONEOS_DEPLOYMENT_TARGET="12.0"
FRAMEWORK_NAME="libxml2"
BUILD_DIR="$(pwd)/build"
FRAMEWORK_DIR="$(pwd)/framework"
SOURCE_DIR="$(pwd)/libxml2-${LIBXML2_VERSION}"

# Create necessary directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${FRAMEWORK_DIR}"

# Download and extract libxml2
if [ ! -d "${SOURCE_DIR}" ]; then
    echo "Downloading libxml2 ${LIBXML2_VERSION}..."
    curl -L "${LIBXML2_DOWNLOAD_URL}" -o "${BUILD_DIR}/libxml2-${LIBXML2_VERSION}.tar.xz"
    tar -xf "${BUILD_DIR}/libxml2-${LIBXML2_VERSION}.tar.xz" -C "$(pwd)"
    rm "${BUILD_DIR}/libxml2-${LIBXML2_VERSION}.tar.xz"
fi

# Function to build for a specific architecture
build_for_arch() {
    ARCH=$1
    PLATFORM=$2
    SDK=$3
    HOST=$4
    
    echo "Building libxml2 for ${ARCH} (${PLATFORM})..."
    
    ARCH_BUILD_DIR="${BUILD_DIR}/${PLATFORM}-${ARCH}"
    mkdir -p "${ARCH_BUILD_DIR}"
    
    SDKROOT=$(xcrun -sdk ${SDK} --show-sdk-path)
    
    export CFLAGS="-arch ${ARCH} -isysroot ${SDKROOT} -miphoneos-version-min=${IPHONEOS_DEPLOYMENT_TARGET} -fembed-bitcode -Wno-error=implicit-function-declaration"
    export LDFLAGS="-arch ${ARCH} -isysroot ${SDKROOT}"
    
    if [ "${PLATFORM}" == "iphonesimulator" ]; then
        export CFLAGS="${CFLAGS} -mios-simulator-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"
    fi
    
    cd "${SOURCE_DIR}"
    
    # Configure with minimal options to reduce size
    ./configure \
        --prefix="${ARCH_BUILD_DIR}" \
        --host="${HOST}" \
        --enable-static \
        --disable-shared \
        --without-python \
        --without-lzma \
        --without-zlib \
        --without-iconv \
        --without-http \
        --without-ftp \
        --disable-dependency-tracking \
        --with-sax1 \
        --with-xpath \
        --with-xptr \
        --with-xinclude \
        --with-pattern \
        --with-tree \
        --with-catalog \
        --with-c14n \
        --with-modules \
        --with-schemas
    
    make clean
    make -j$(sysctl -n hw.ncpu)
    make install
    
    cd - > /dev/null
}

# Build for different architectures
build_for_arch "arm64" "iphoneos" "iphoneos" "arm-apple-darwin"
build_for_arch "x86_64" "iphonesimulator" "iphonesimulator" "x86_64-apple-darwin"
build_for_arch "arm64" "iphonesimulator" "iphonesimulator" "arm-apple-darwin"

# Create device and simulator framework directories
DEVICE_FRAMEWORK_DIR="${FRAMEWORK_DIR}/iphoneos"
SIMULATOR_FRAMEWORK_DIR="${FRAMEWORK_DIR}/iphonesimulator"

mkdir -p "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/Headers"
mkdir -p "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/Headers"

# Create fat library for simulator (x86_64 + arm64)
echo "Creating fat library for simulator..."
lipo -create \
    "${BUILD_DIR}/iphonesimulator-x86_64/lib/libxml2.a" \
    "${BUILD_DIR}/iphonesimulator-arm64/lib/libxml2.a" \
    -output "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

# Copy device library
cp "${BUILD_DIR}/iphoneos-arm64/lib/libxml2.a" "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

# Copy headers to both frameworks
cp -R "${BUILD_DIR}/iphoneos-arm64/include/libxml2/libxml" "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/Headers/"
cp -R "${BUILD_DIR}/iphoneos-arm64/include/libxml2/libxml" "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework/Headers/"

# Create Info.plist for both frameworks
create_info_plist() {
    FRAMEWORK_PATH=$1
    
    cat > "${FRAMEWORK_PATH}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>org.xmlsoft.libxml2</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>${LIBXML2_VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${LIBXML2_VERSION}</string>
    <key>MinimumOSVersion</key>
    <string>${IPHONEOS_DEPLOYMENT_TARGET}</string>
</dict>
</plist>
EOF
}

create_info_plist "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework"
create_info_plist "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework"

# Create module map for both frameworks
create_module_map() {
    FRAMEWORK_PATH=$1
    
    mkdir -p "${FRAMEWORK_PATH}/Modules"
    cat > "${FRAMEWORK_PATH}/Modules/module.modulemap" << EOF
framework module libxml2 [system] {
  umbrella header "libxml/xmlversion.h"
  export *
  module * { export * }
}
EOF
}

create_module_map "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework"
create_module_map "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework"

# Create XCFramework with both device and simulator frameworks
echo "Creating XCFramework..."
xcrun xcodebuild -create-xcframework \
    -framework "${DEVICE_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework" \
    -framework "${SIMULATOR_FRAMEWORK_DIR}/${FRAMEWORK_NAME}.framework" \
    -output "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}.xcframework"

echo "Cleaning up..."
rm -rf "${BUILD_DIR}"
rm -rf "${DEVICE_FRAMEWORK_DIR}"
rm -rf "${SIMULATOR_FRAMEWORK_DIR}"

echo "Done! libxml2 XCFramework is available at: ${FRAMEWORK_DIR}/${FRAMEWORK_NAME}.xcframework" 