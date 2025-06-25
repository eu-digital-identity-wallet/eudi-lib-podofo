#!/bin/bash
set -e

# PoDoFo Configuration
PODOFO_VERSION="master"
PODOFO_REPO_NAME="EUDI_PoDoFo"

# Download and extract podofo if not already present
if [ ! -d "podofo-${PODOFO_VERSION}" ]; then
    echo "Downloading podofo-${PODOFO_VERSION}..."
    curl -L "https://github.com/hectorgat/EUDI_PoDoFo/archive/refs/heads/${PODOFO_VERSION}.zip" -o "podofo-${PODOFO_VERSION}.zip"
    unzip "podofo-${PODOFO_VERSION}.zip"

    # Only move the directory if the names are different
    if [ PODOFO_REPO_NAME != "podofo" ]; then
        mv "${PODOFO_REPO_NAME}-${PODOFO_VERSION}" "podofo-${PODOFO_VERSION}"
    fi
fi

# Define architectures and platforms
DEVICE_ARCHS="arm64"
SIMULATOR_ARCHS="arm64"
PLATFORMS="iphoneos iphonesimulator"

# Define paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
INSTALL_DIR="${SCRIPT_DIR}/install"
XCFRAMEWORK_DIR="${SCRIPT_DIR}/xcframework"
PODOFO_SRC_DIR="$(cd "${SCRIPT_DIR}/podofo-${PODOFO_VERSION}" && pwd)"


# Dependency paths
## iOS
ZLIB_INCLUDE_DIR_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/zlib.xcframework/ios-arm64/Headers"
ZLIB_LIBRARY_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/zlib.xcframework/ios-arm64/libz.a"
OPENSSL_ROOT_DIR_IOS="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks"
OPENSSL_INCLUDE_DIR_IOS="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64/Headers"
OPENSSL_SSL_LIBRARY_IOS="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/SSL.xcframework/ios-arm64/libssl.a"
OPENSSL_CRYPTO_LIBRARY_IOS="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64/libcrypto.a"
OPENSSL_LIBRARIES_IOS="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/SSL.xcframework/ios-arm64/libssl.a;/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64/libcrypto.a"
FREETYPE_INCLUDE_DIRS_IOS="/Users/pkokkinakis/Desktop/PoDoFo/freetype/build/ios/xcframework/FreeType.xcframework/ios-arm64/Headers"
FREETYPE_LIBRARY_IOS="/Users/pkokkinakis/Desktop/PoDoFo/freetype/build/ios/xcframework/FreeType.xcframework/ios-arm64/libfreetype.a"
LIBXML2_INCLUDE_DIR_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libxml2/framework/libxml2.xcframework/ios-arm64/libxml2.framework/Headers"
LIBXML2_LIBRARIES_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libxml2/framework/libxml2.xcframework/ios-arm64/libxml2.framework/libxml2"
PNG_PNG_INCLUDE_DIR_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/libpng.xcframework/ios-arm64/Headers"
PNG_LIBRARY_IOS="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/libpng.xcframework/ios-arm64/libpng16.a"

## Simulator
ZLIB_INCLUDE_DIR_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/zlib.xcframework/ios-arm64_x86_64-simulator/Headers"
ZLIB_LIBRARY_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/zlib.xcframework/ios-arm64_x86_64-simulator/libz.a"
OPENSSL_ROOT_DIR_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks"
OPENSSL_INCLUDE_DIR_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64_x86_64-simulator/Headers"
OPENSSL_SSL_LIBRARY_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/SSL.xcframework/ios-arm64_x86_64-simulator/libssl.a"
OPENSSL_CRYPTO_LIBRARY_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64_x86_64-simulator/libcrypto.a"
OPENSSL_LIBRARIES_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/SSL.xcframework/ios-arm64_x86_64-simulator/libssl.a;/Users/pkokkinakis/Desktop/PoDoFo/openssl/frameworks/Crypto.xcframework/ios-arm64_x86_64-simulator/libcrypto.a"
FREETYPE_INCLUDE_DIRS_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/freetype/build/ios/xcframework/FreeType.xcframework/ios-arm64_x86_64-simulator/Headers"
FREETYPE_LIBRARY_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/freetype/build/ios/xcframework/FreeType.xcframework/ios-arm64_x86_64-simulator/libfreetype_simulator.a"
LIBXML2_INCLUDE_DIR_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libxml2/framework/libxml2.xcframework/ios-arm64_x86_64-simulator/libxml2.framework/Headers"
LIBXML2_LIBRARIES_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libxml2/framework/libxml2.xcframework/ios-arm64_x86_64-simulator/libxml2.framework/libxml2"
PNG_PNG_INCLUDE_DIR_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/libpng.xcframework/ios-arm64_x86_64-simulator/Headers"
PNG_LIBRARY_SIMULATOR="/Users/pkokkinakis/Desktop/PoDoFo/libpng/xcframework/libpng.xcframework/ios-arm64_x86_64-simulator/libpng16.a"


# Function to map platform to framework directory name
map_platform_dir() {
    local platform=$1
    if [ "$platform" == "iphoneos" ]; then
        echo "ios-arm64"
    elif [ "$platform" == "iphonesimulator" ]; then
        echo "ios-arm64-simulator"  # Changed to reflect that we're only using arm64 for simulator
    else
        echo "unknown"
    fi
}

# Function to build for a specific platform and architecture
build_for_platform_arch() {
    local platform=$1
    local arch=$2

    echo "Building PoDoFo for $platform $arch..."

    local build_dir="${BUILD_DIR}/${platform}-${arch}"
    local install_dir="${INSTALL_DIR}/${platform}-${arch}"

    mkdir -p "$build_dir"
    cd "$build_dir"

    # Base CMake arguments common to all platforms
    CMAKE_ARGS=(
        "-DCMAKE_TOOLCHAIN_FILE=${build_dir}/../../ios.toolchain.cmake"
        "-DCMAKE_INSTALL_PREFIX=${install_dir}"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DPODOFO_BUILD_STATIC=ON"
        "-DPODOFO_BUILD_LIB_ONLY=ON"
        "-DPODOFO_BUILD_TEST=OFF"
        "-DPODOFO_BUILD_EXAMPLES=OFF"
        "-DPODOFO_BUILD_UNSUPPORTED_TOOLS=OFF"
        "-DPODOFO_HAVE_JPEG_LIB=OFF"
        "-DPODOFO_HAVE_TIFF_LIB=OFF"
        "-DPODOFO_HAVE_PNG_LIB=ON"
        "-DPODOFO_HAVE_FONTCONFIG=OFF"
        "-DCMAKE_SYSTEM_NAME=iOS"
        "-DPLATFORM=${platform}"
        "-DDEPLOYMENT_TARGET=16.5"
        "-DENABLE_BITCODE=OFF"
        "-DENABLE_ARC=OFF"
        "-DENABLE_VISIBILITY=OFF"
        "-DENABLE_STRICT_TRY_COMPILE=OFF"
        "-DARCHS=${arch}"
    )

    # Set platform-specific paths
    if [ "$platform" == "iphoneos" ]; then
        # Device-specific paths
        CMAKE_ARGS+=(
            "-DZLIB_INCLUDE_DIR=${ZLIB_INCLUDE_DIR_IOS}"
            "-DZLIB_LIBRARY=${ZLIB_LIBRARY_IOS}"
            "-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR_IOS}"
            "-DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR_IOS}"
            "-DOPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY_IOS}"
            "-DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY_IOS}"
            "-DOPENSSL_LIBRARIES=${OPENSSL_LIBRARIES_IOS}"
            "-DFREETYPE_INCLUDE_DIRS=${FREETYPE_INCLUDE_DIRS_IOS}"
            "-DFREETYPE_LIBRARY=${FREETYPE_LIBRARY_IOS}"
            "-DLIBXML2_INCLUDE_DIR=${LIBXML2_INCLUDE_DIR_IOS}"
            "-DLIBXML2_LIBRARIES=${LIBXML2_LIBRARIES_IOS}"
            "-DPNG_PNG_INCLUDE_DIR=${PNG_PNG_INCLUDE_DIR_IOS}"
            "-DPNG_LIBRARY=${PNG_LIBRARY_IOS}"
        )
    elif [ "$platform" == "iphonesimulator" ]; then
        # Simulator-specific paths
        CMAKE_ARGS+=(
        		"-DZLIB_INCLUDE_DIR=${ZLIB_INCLUDE_DIR_SIMULATOR}"
						"-DZLIB_LIBRARY=${ZLIB_LIBRARY_SIMULATOR}"
						"-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR_SIMULATOR}"
						"-DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR_SIMULATOR}"
						"-DOPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY_SIMULATOR}"
						"-DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY_SIMULATOR}"
						"-DOPENSSL_LIBRARIES=${OPENSSL_LIBRARIES_SIMULATOR}"
						"-DFREETYPE_INCLUDE_DIRS=${FREETYPE_INCLUDE_DIRS_SIMULATOR}"
						"-DFREETYPE_LIBRARY=${FREETYPE_LIBRARY_SIMULATOR}"
						"-DLIBXML2_INCLUDE_DIR=${LIBXML2_INCLUDE_DIR_SIMULATOR}"
						"-DLIBXML2_LIBRARIES=${LIBXML2_LIBRARIES_SIMULATOR}"
						"-DPNG_PNG_INCLUDE_DIR=${PNG_PNG_INCLUDE_DIR_SIMULATOR}"
						"-DPNG_LIBRARY=${PNG_LIBRARY_SIMULATOR}"
        )
    fi

    echo "Running CMake with arguments: ${CMAKE_ARGS[@]}"
    cmake -S "${PODOFO_SRC_DIR}" "${CMAKE_ARGS[@]}"
    cmake --build . --config Release
    cmake --install .

    cd "${SCRIPT_DIR}"

    # Copy missing openssl party headers
    if [ "$platform" == "iphoneos" ]; then
      cp -R "${OPENSSL_INCLUDE_DIR_IOS}/openssl" "${INSTALL_DIR}/iphoneos-arm64/include/"
    elif [ "$platform" == "iphonesimulator" ]; then
      cp -R "${OPENSSL_INCLUDE_DIR_SIMULATOR}/openssl" "${INSTALL_DIR}/iphonesimulator-arm64/include/"
    fi
}

# Clean previous builds
rm -rf "${XCFRAMEWORK_DIR}"
mkdir -p "${XCFRAMEWORK_DIR}"

# Build for device (arm64)
echo "Building for iOS device (arm64)..."
for arch in $DEVICE_ARCHS; do
    build_for_platform_arch "iphoneos" "$arch"
done

# Build for simulator (arm64 only)
echo "Building for iOS simulator..."
for arch in $SIMULATOR_ARCHS; do
    build_for_platform_arch "iphonesimulator" "$arch"
done

# Create XCFramework structure
echo "Creating XCFramework structure..."

# Create framework directories with proper structure
DEVICE_FRAMEWORK_DIR="${XCFRAMEWORK_DIR}/PoDoFo.xcframework/ios-arm64/PoDoFo.framework"
SIMULATOR_FRAMEWORK_DIR="${XCFRAMEWORK_DIR}/PoDoFo.xcframework/ios-arm64-simulator/PoDoFo.framework"

mkdir -p "${DEVICE_FRAMEWORK_DIR}/Headers"
mkdir -p "${SIMULATOR_FRAMEWORK_DIR}/Headers"

# Create module map for device
mkdir -p "${DEVICE_FRAMEWORK_DIR}/Modules"
cat > "${DEVICE_FRAMEWORK_DIR}/Modules/module.modulemap" << EOF
framework module PoDoFo {
    umbrella header "PodofoWrapper.h"
    explicit module Base {
        header "PodofoWrapper.h"
        export *
    }
    export *
    link "c++"
    link "c++abi"
}
EOF

# Create module map for simulator
mkdir -p "${SIMULATOR_FRAMEWORK_DIR}/Modules"
cat > "${SIMULATOR_FRAMEWORK_DIR}/Modules/module.modulemap" << EOF
framework module PoDoFo {
    umbrella header "PodofoWrapper.h"
    explicit module Base {
        header "PodofoWrapper.h"
        export *
    }
    export *
    link "c++"
    link "c++abi"
}
EOF

# Copy headers and libraries
cp -R "${INSTALL_DIR}/iphoneos-arm64/include/podofo/" "${DEVICE_FRAMEWORK_DIR}/Headers/"
cp -R "${INSTALL_DIR}/iphonesimulator-arm64/include/podofo/" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"
cp -R "${OPENSSL_INCLUDE_DIR_IOS}/openssl" "${DEVICE_FRAMEWORK_DIR}/Headers/"
cp -R "${OPENSSL_INCLUDE_DIR_SIMULATOR}/openssl" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"

# Compile PodofoWrapper class for device
echo "Compiling PodofoWrapper class for device..."
clang++ -c "${SCRIPT_DIR}/PodofoWrapper.mm" \
    -o "${BUILD_DIR}/iphoneos-arm64/PodofoWrapper.o" \
    -I"${SCRIPT_DIR}" \
    -I"${INSTALL_DIR}/iphoneos-arm64/include" \
    -I"${PNG_PNG_INCLUDE_DIR_IOS}" \
    -I"${ZLIB_INCLUDE_DIR_IOS}" \
    -arch arm64 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    -fobjc-arc \
    -fmodules \
    -fobjc-abi-version=2 \
    -fobjc-runtime=ios-16.5 \
    -std=c++17 \
    -stdlib=libc++ \
    -I$(xcrun --sdk iphoneos --show-sdk-path)/usr/include/c++/v1

# Compile PodofoWrapper class for simulator
echo "Compiling Podofo class for simulator..."
clang++ -c "${SCRIPT_DIR}/PodofoWrapper.mm" \
    -o "${BUILD_DIR}/iphonesimulator-arm64/PodofoWrapper.o" \
    -I"${SCRIPT_DIR}" \
    -I"${INSTALL_DIR}/iphonesimulator-arm64/include" \
    -I"${PNG_PNG_INCLUDE_DIR_SIMULATOR}" \
    -I"${ZLIB_INCLUDE_DIR_SIMULATOR}" \
    -arch arm64 \
    -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
    -fobjc-arc \
    -fmodules \
    -fobjc-abi-version=2 \
    -fobjc-runtime=ios-16.5 \
    -std=c++17 \
    -stdlib=libc++ \
    -I$(xcrun --sdk iphonesimulator --show-sdk-path)/usr/include/c++/v1

# Copy PodofoWrapper header to framework
cp "${SCRIPT_DIR}/PodofoWrapper.h" "${DEVICE_FRAMEWORK_DIR}/Headers/"
cp "${SCRIPT_DIR}/PodofoWrapper.h" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"

# Combine all libraries into a single static library for each platform
echo "Combining libraries for device..."
libtool -static -o "${DEVICE_FRAMEWORK_DIR}/PoDoFo" \
    "${INSTALL_DIR}/iphoneos-arm64/lib/libpodofo.a" \
    "${INSTALL_DIR}/iphoneos-arm64/lib/libpodofo_private.a" \
    "${INSTALL_DIR}/iphoneos-arm64/lib/libpodofo_3rdparty.a" \
    "${BUILD_DIR}/iphoneos-arm64/PodofoWrapper.o" \
    "${ZLIB_LIBRARY_IOS}" \
    "${OPENSSL_SSL_LIBRARY_IOS}" \
    "${OPENSSL_CRYPTO_LIBRARY_IOS}" \
    ${OPENSSL_LIBRARIES_IOS//;/ } \
    "${FREETYPE_LIBRARY_IOS}" \
    "${PNG_LIBRARY_IOS}" \
    "${LIBXML2_LIBRARIES_IOS}"

echo "Combining libraries for simulator..."
libtool -static -o "${SIMULATOR_FRAMEWORK_DIR}/PoDoFo" \
    "${INSTALL_DIR}/iphonesimulator-arm64/lib/libpodofo.a" \
    "${INSTALL_DIR}/iphonesimulator-arm64/lib/libpodofo_private.a" \
    "${INSTALL_DIR}/iphonesimulator-arm64/lib/libpodofo_3rdparty.a" \
    "${BUILD_DIR}/iphonesimulator-arm64/PodofoWrapper.o" \
    "${ZLIB_LIBRARY_SIMULATOR}" \
    "${OPENSSL_SSL_LIBRARY_SIMULATOR}" \
    "${OPENSSL_CRYPTO_LIBRARY_SIMULATOR}" \
    ${OPENSSL_LIBRARIES_SIMULATOR//;/ } \
    "${FREETYPE_LIBRARY_SIMULATOR}" \
    "${PNG_LIBRARY_SIMULATOR}" \
    "${LIBXML2_LIBRARIES_SIMULATOR}"


# Create Info.plist files
cat > "${DEVICE_FRAMEWORK_DIR}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>PoDoFo</string>
    <key>CFBundleIdentifier</key>
    <string>org.podofo.PoDoFo</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>PoDoFo</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>16.5</string>
</dict>
</plist>
EOF

cp "${DEVICE_FRAMEWORK_DIR}/Info.plist" "${SIMULATOR_FRAMEWORK_DIR}/Info.plist"

# Create XCFramework Info.plist
cat > "${XCFRAMEWORK_DIR}/PoDoFo.xcframework/Info.plist" << EOF
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
            <string>PoDoFo.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64-simulator</string>
            <key>LibraryPath</key>
            <string>PoDoFo.framework</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
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
    <key>CFBundleName</key>
    <string>PoDoFo</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>
EOF

echo "XCFramework created at: ${XCFRAMEWORK_DIR}/PoDoFo.xcframework"