#!/bin/bash

# Exit on error
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

NDK_DIR="$1"
TARGET_DIR="$2"
OPENSSL_VERSION="$3"

# Convert TARGET_DIR to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"

BUILD_DIR="$TARGET_DIR/build"
DOWNLOAD_DIR="$TARGET_DIR/download"
INSTALL_DIR="$TARGET_DIR/install"

API_LEVEL=21
# Define architectures and their corresponding OpenSSL targets
ARCHS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
TARGETS=("android-arm64" "android-arm" "android-x86" "android-x86_64")
COMPILERS=(
    "aarch64-linux-android$API_LEVEL-clang"
    "armv7a-linux-androideabi$API_LEVEL-clang"
    "i686-linux-android$API_LEVEL-clang"
    "x86_64-linux-android$API_LEVEL-clang"
)

function check() {
    # Check that NDK_DIR argument has been passed
    if [ -z "$NDK_DIR" ]; then
        echo "Error: NDK_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <OPENSSL_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <OPENSSL_VERSION>"
        exit 1
    fi

    # Check that OPENSSL_VERSION argument has been passed
    if [ -z "$OPENSSL_VERSION" ]; then
        echo "Error: OPENSSL_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <OPENSSL_VERSION>"
        exit 1
    fi

    # Check if NDK exists
    if [ ! -d "$NDK_DIR" ]; then
        echo "Error: Android NDK directory not found at $NDK_DIR"
        echo "Please provide a valid path to the Android NDK directory"
        exit 1
    fi
}

function prepare() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"

    # Download OpenSSL if not present
    if [ ! -f "-C "$DOWNLOAD_DIR"/openssl-$OPENSSL_VERSION.tar.gz" ]; then
        curl -L "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" -o "$DOWNLOAD_DIR/openssl-$OPENSSL_VERSION.tar.gz" 
    fi

    # Extract OpenSSL
    if [ ! -d "$BUILD_DIR/openssl-$OPENSSL_VERSION" ]; then
        tar xzf "$DOWNLOAD_DIR/openssl-$OPENSSL_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    # Set up toolchain
    TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"

    # Build for each architecture
    for i in "${!ARCHS[@]}"; do
        ABI="${ARCHS[$i]}"
        TARGET="${TARGETS[$i]}"
        CC="${COMPILERS[$i]}"
        CXX="${CC}++"
        
        echo "Building for $ABI..."
        
        # Set up environment variables for current architecture
        export PATH="$TOOLCHAIN/bin:$PATH"
        export ANDROID_NDK_ROOT="$NDK_DIR"
        export CC="$CC"
        export CXX="$CXX"
        export CFLAGS="-fPIC"
        export LDFLAGS="-Wl,-z,max-page-size=16384"

        # Configure OpenSSL
        cd "$BUILD_DIR/openssl-$OPENSSL_VERSION"
        ./Configure $TARGET \
            --prefix="$INSTALL_DIR/$ABI" \
            --openssldir="$INSTALL_DIR/$ABI" \
            threads \
            -D__ANDROID_API__=$API_LEVEL

        # Build OpenSSL
        make clean
        make -j$(nproc)
        make install_sw

        cd ..
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
cat > "$INSTALL_DIR/OpenSSL-config.cmake" << EOF
set(OPENSSL_INCLUDE_DIR "\${CMAKE_CURRENT_LIST_DIR}/include")
set(OPENSSL_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libcrypto.so" "\${CMAKE_CURRENT_LIST_DIR}/lib/libssl.so")
set(OPENSSL_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/openssl.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: OpenSSL
Description: Secure Sockets Layer and cryptography libraries
Version: 3.2.1
Libs: -L\${libdir} -lssl -lcrypto
Libs.private: -ldl
Cflags: -I\${includedir}
EOF

    echo "Installation completed successfully!"
    echo "CMake and pkg-config files are available in: $INSTALL_DIR" 
}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
