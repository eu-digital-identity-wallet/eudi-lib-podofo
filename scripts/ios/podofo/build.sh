#!/bin/bash
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
FREETYPE_DIR="$2"
LIBPNG_DIR="$3"
LIBXML2_DIR="$4"
OPENSSL_DIR="$5"
ZLIB_DIR="$6"
MIN_IOS_VERSION="16.5"

# Define architectures and platforms
DEVICE_ARCHS="arm64"
SIMULATOR_ARCHS="arm64"
PLATFORMS="iphoneos iphonesimulator"

# Convert input dirs to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"
FREETYPE_DIR="$(cd "$(dirname "$FREETYPE_DIR")" && pwd)/$(basename "$FREETYPE_DIR")"
LIBPNG_DIR="$(cd "$(dirname "$LIBPNG_DIR")" && pwd)/$(basename "$LIBPNG_DIR")"
LIBXML2_DIR="$(cd "$(dirname "$LIBXML2_DIR")" && pwd)/$(basename "$LIBXML2_DIR")"
OPENSSL_DIR="$(cd "$(dirname "$OPENSSL_DIR")" && pwd)/$(basename "$OPENSSL_DIR")"
ZLIB_DIR="$(cd "$(dirname "$ZLIB_DIR")" && pwd)/$(basename "$ZLIB_DIR")"

# Define directories
BUILD_DIR="$TARGET_DIR/build"
INSTALL_DIR="$TARGET_DIR/install"
FRAMEWORK_DIR="$INSTALL_DIR/xcframework"
SOURCE_DIR=$(pwd)

function check() {
    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi

    # Check that FREETYPE_DIR argument has been passed
    if [ -z "$FREETYPE_DIR" ]; then
        echo "Error: FREETYPE_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi

    # Check that LIBPNG_DIR argument has been passed
    if [ -z "$LIBPNG_DIR" ]; then
        echo "Error: LIBPNG_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi

    # Check that LIBXML2_DIR argument has been passed
    if [ -z "$LIBXML2_DIR" ]; then
        echo "Error: LIBXML2_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi

    # Check that OPENSSL_DIR argument has been passed
    if [ -z "$OPENSSL_DIR" ]; then
        echo "Error: OPENSSL_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi

    # Check that ZLIB_DIR argument has been passed
    if [ -z "$ZLIB_DIR" ]; then
        echo "Error: ZLIB_DIR argument not provided."
        echo "Usage: $0 <TARGET_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR> <ZLIB_DIR>"
        exit 1
    fi
}

function prepare() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$FRAMEWORK_DIR"
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$FRAMEWORK_DIR"

    # Function to build for a specific platform and architecture
    build_for_platform_arch() {
        local platform=$1
        local arch=$2

        echo "Building PoDoFo for $platform $arch..."

        local install_dir="${INSTALL_DIR}/${platform}-${arch}"

        mkdir -p "$install_dir"

        # Handle devide and simulator paths
        if [ "$platform" == "iphoneos" ]; then
            sim_suffix=""
            libft_suffix=""
        else
            sim_suffix="_x86_64-simulator"
            libft_suffix="_simulator"
        fi

        # Base CMake arguments common to all platforms
        CMAKE_ARGS=(
            "-DCMAKE_TOOLCHAIN_FILE=${SOURCE_DIR}/scripts/ios/podofo/ios.toolchain.cmake"
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
            "-DDEPLOYMENT_TARGET=${MIN_IOS_VERSION}"
            "-DENABLE_BITCODE=OFF"
            "-DENABLE_ARC=OFF"
            "-DENABLE_VISIBILITY=OFF"
            "-DENABLE_STRICT_TRY_COMPILE=OFF"
            "-DARCHS=${arch}"
            "-DZLIB_INCLUDE_DIR=${ZLIB_DIR}/xcframework/zlib.xcframework/ios-${arch}${sim_suffix}/Headers"
            "-DZLIB_LIBRARY=${ZLIB_DIR}/xcframework/zlib.xcframework/ios-${arch}${sim_suffix}/libz.a"
            "-DOPENSSL_ROOT_DIR=${OPENSSL_DIR}/xcframework"
            "-DOPENSSL_INCLUDE_DIR=${OPENSSL_DIR}/xcframework/SSL.xcframework/ios-${arch}${sim_suffix}/Headers"
            "-DOPENSSL_SSL_LIBRARY=${OPENSSL_DIR}/xcframework/SSL.xcframework/ios-${arch}${sim_suffix}/libssl.a"
            "-DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_DIR}/xcframework/Crypto.xcframework/ios-${arch}${sim_suffix}/libcrypto.a"
            "-DOPENSSL_LIBRARIES=${OPENSSL_DIR}/xcframework/SSL.xcframework/ios-${arch}${sim_suffix}/libssl.a;${OPENSSL_DIR}/xcframework/Crypto.xcframework/ios-${arch}${sim_suffix}/libcrypto.a"
            "-DFREETYPE_INCLUDE_DIRS=${FREETYPE_DIR}/xcframework/FreeType.xcframework/ios-${arch}${sim_suffix}/Headers"
            "-DFREETYPE_LIBRARY=${FREETYPE_DIR}/xcframework/FreeType.xcframework/ios-${arch}${sim_suffix}/libfreetype.a"
            "-DLIBXML2_INCLUDE_DIR=${LIBXML2_DIR}/xcframework/libxml2.xcframework/ios-${arch}${sim_suffix}/libxml2.framework/Headers"
            "-DLIBXML2_LIBRARIES=${LIBXML2_DIR}/xcframework/libxml2.xcframework/ios-${arch}${sim_suffix}/libxml2.framework/libxml2"
            "-DPNG_PNG_INCLUDE_DIR=${LIBPNG_DIR}/xcframework/libpng.xcframework/ios-${arch}${sim_suffix}/Headers"
            "-DPNG_LIBRARY=${LIBPNG_DIR}/xcframework/libpng.xcframework/ios-${arch}${sim_suffix}/libpng16.a"
        )

        echo "Running CMake with arguments: ${CMAKE_ARGS[@]}"
        cmake -S "${SOURCE_DIR}" "${CMAKE_ARGS[@]}"
        cmake --build . --config Release
        cmake --install .

        cp -R "${OPENSSL_DIR}/xcframework/SSL.xcframework/ios-${arch}${sim_suffix}/Headers/openssl" "${INSTALL_DIR}/${platform}-${arch}/include/"
    }

    # Build for device
    for arch in $DEVICE_ARCHS; do
        echo "Building for iOS device ($arch)..."
        build_for_platform_arch "iphoneos" "$arch"
    done

    # Build for simulator
    for arch in $SIMULATOR_ARCHS; do
        echo "Building for iOS simulator ($arch)..."
        build_for_platform_arch "iphonesimulator" "$arch"
    done

    # Create XCFramework structure
    echo "Creating XCFramework structure..."

    # Create framework directories with proper structure
    DEVICE_FRAMEWORK_DIR="${FRAMEWORK_DIR}/PoDoFo.xcframework/ios-arm64/PoDoFo.framework"
    SIMULATOR_FRAMEWORK_DIR="${FRAMEWORK_DIR}/PoDoFo.xcframework/ios-arm64-simulator/PoDoFo.framework"

    # Make framework folders
    mkdir -p "${DEVICE_FRAMEWORK_DIR}/Headers" "${SIMULATOR_FRAMEWORK_DIR}/Headers"

    createModuleMapFile() {
        local framework_dir=$1

        mkdir -p "${framework_dir}/Modules"
        cat > "${framework_dir}/Modules/module.modulemap" << EOF
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
    }

    createModuleMapFile "$DEVICE_FRAMEWORK_DIR"
    createModuleMapFile "$SIMULATOR_FRAMEWORK_DIR"

    # Copy headers and libraries
    cp -R "${INSTALL_DIR}/iphoneos-arm64/include/podofo/" "${DEVICE_FRAMEWORK_DIR}/Headers/"
    cp -R "${INSTALL_DIR}/iphonesimulator-arm64/include/podofo/" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"
    cp -R "${INSTALL_DIR}/iphoneos-arm64/include/openssl" "${DEVICE_FRAMEWORK_DIR}/Headers/"
    cp -R "${INSTALL_DIR}/iphonesimulator-arm64/include/openssl" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"

    compilePodofoWrapper() {
        local platform=$1
        local arch=$2

        # Compile PodofoWrapper class
        echo "Compiling PodofoWrapper class for ($platform/$arch)..."

        clang++ -c "${SOURCE_DIR}/scripts/ios/podofo/PodofoWrapper.mm" \
            -o "${INSTALL_DIR}/${platform}-${arch}/PodofoWrapper.o" \
            -I"${SOURCE_DIR}" \
            -I"${INSTALL_DIR}/${platform}-${arch}/include" \
            -I"${LIBPNG_DIR}/xcframework/libpng.xcframework/ios-${arch}${sim_suffix}/Headers" \
            -I"${ZLIB_DIR}/xcframework/zlib.xcframework/ios-${arch}${sim_suffix}/Headers" \
            -arch "${arch}" \
            -isysroot $(xcrun --sdk "${platform}" --show-sdk-path) \
            -fobjc-arc \
            -fmodules \
            -fobjc-abi-version=2 \
            -fobjc-runtime=ios-16.5 \
            -std=c++17 \
            -stdlib=libc++ \
            -I$(xcrun --sdk "${platform}" --show-sdk-path)/usr/include/c++/v1
    }

    compilePodofoWrapper "iphoneos" "arm64"
    compilePodofoWrapper "iphonesimulator" "arm64"

    # Copy PodofoWrapper header to framework
    cp "${SOURCE_DIR}/scripts/ios/podofo/PodofoWrapper.h" "${DEVICE_FRAMEWORK_DIR}/Headers/"
    cp "${SOURCE_DIR}/scripts/ios/podofo/PodofoWrapper.h" "${SIMULATOR_FRAMEWORK_DIR}/Headers/"

    combineDependenciesInPoDoFo() {
        local platform=$1
        local arch=$2
        local framework_dir=$3

        # Handle devide and simulator paths
        if [ "$platform" == "iphoneos" ]; then
            sim_suffix=""
            libft_suffix=""
        else
            sim_suffix="_x86_64-simulator"
            libft_suffix="_simulator"
        fi

        # Combine all libraries into a single static library
        echo "Combining libraries for (${platform}/${arch})..."
        echo "simsuffix: ${sim_suffix}"
        echo "libft_suffix: ${libft_suffix}"

        libtool -static -o "${framework_dir}/PoDoFo" \
            "${INSTALL_DIR}/${platform}-${arch}/lib/libpodofo.a" \
            "${INSTALL_DIR}/${platform}-${arch}/lib/libpodofo_private.a" \
            "${INSTALL_DIR}/${platform}-${arch}/lib/libpodofo_3rdparty.a" \
            "${INSTALL_DIR}/${platform}-${arch}/PodofoWrapper.o" \
            "${ZLIB_DIR}/xcframework/zlib.xcframework/ios-${arch}${sim_suffix}/libz.a" \
            "${OPENSSL_DIR}/xcframework/SSL.xcframework/ios-${arch}${sim_suffix}/libssl.a" \
            "${OPENSSL_DIR}/xcframework/Crypto.xcframework/ios-${arch}${sim_suffix}/libcrypto.a" \
            "${FREETYPE_DIR}/xcframework/FreeType.xcframework/ios-${arch}${sim_suffix}/libfreetype${libft_suffix}.a" \
            "${LIBPNG_DIR}/xcframework/libpng.xcframework/ios-${arch}${sim_suffix}/libpng16.a" \
            "${LIBXML2_DIR}/xcframework/libxml2.xcframework/ios-${arch}${sim_suffix}/libxml2.framework/libxml2"
    }

    combineDependenciesInPoDoFo "iphoneos" "arm64" "${DEVICE_FRAMEWORK_DIR}"
    combineDependenciesInPoDoFo "iphonesimulator" "arm64" "${SIMULATOR_FRAMEWORK_DIR}"


    createInnerInfoPlistFile() {
        local framework_dir=$1

        # Create Info.plist files
        cat > "${framework_dir}/Info.plist" << EOF
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
    }

    createInnerInfoPlistFile "${DEVICE_FRAMEWORK_DIR}"
    createInnerInfoPlistFile "${SIMULATOR_FRAMEWORK_DIR}"

    # Create Main XCFramework Info.plist
    cat > "${FRAMEWORK_DIR}/PoDoFo.xcframework/Info.plist" << EOF
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

    echo "XCFramework created at: ${FRAMEWORK_DIR}/PoDoFo.xcframework"
}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
