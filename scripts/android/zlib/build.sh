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
ZLIB_VERSION="$3"

# Convert TARGET_DIR to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"

# Define directories
BUILD_DIR="$TARGET_DIR/build"
DOWNLOAD_DIR="$TARGET_DIR/download"
INSTALL_DIR="$TARGET_DIR/install"

# Define architectures to build for
ARCHS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
API_LEVEL=21

function check() {
    # Check that NDK_DIR argument has been passed
    if [ -z "$NDK_DIR" ]; then
        echo "Error: NDK_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <ZLIB_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <ZLIB_VERSION>"
        exit 1
    fi

    # Check that ZLIB_VERSION argument has been passed
    if [ -z "$ZLIB_VERSION" ]; then
        echo "Error: ZLIB_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <ZLIB_VERSION>"
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

    # Download zlib if not already present
    if [ ! -f "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION.tar.gz" ]; then
        echo "Downloading zlib..."
        curl -L "https://github.com/madler/zlib/archive/refs/tags/v$ZLIB_VERSION.tar.gz" -o "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION.tar.gz"
    fi

    # Extract zlib if not already extracted
    if [ ! -d "$BUILD_DIR/zlib-$ZLIB_VERSION" ]; then
        echo "Extracting zlib..."
        tar xzf "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Build for each architecture
    for ABI in "${ARCHS[@]}"; do
        echo "Building for $ABI..."
        
        # Set up toolchain and compiler
        case $ABI in
            "arm64-v8a")
                HOST="aarch64-linux-android"
                ;;
            "armeabi-v7a")
                HOST="armv7a-linux-androideabi"
                ;;
            "x86")
                HOST="i686-linux-android"
                ;;
            "x86_64")
                HOST="x86_64-linux-android"
                ;;
        esac
        
        # Set up compiler and tools
        CC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/${HOST}${API_LEVEL}-clang"
        CXX="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/${HOST}${API_LEVEL}-clang++"
        AR="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
        RANLIB="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib"
        STRIP="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
        
        # Set up sysroot
        SYSROOT="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
        
        # Create build directory for this architecture
        ARCH_BUILD_DIR="$BUILD_DIR/$ABI"
        mkdir -p "$ARCH_BUILD_DIR"
        cd "$ARCH_BUILD_DIR"
        
        # Copy source files
        cp -r "$BUILD_DIR/zlib-$ZLIB_VERSION"/* .
        
        # Configure zlib for cross-compilation
        CHOST="$HOST" \
        CC="$CC" \
        CFLAGS="-fPIC -O3" \
        ./configure --static --prefix="$INSTALL_DIR/$ABI"
        
        # Build and install
        make clean
        make
        make install
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
    cat > "$INSTALL_DIR/zlib-config.cmake" << EOF
set(ZLIB_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(ZLIB_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libz.a")
set(ZLIB_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/zlib.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: zlib
Description: A Massively Spiffy Yet Delicately Unobtrusive Compression Library
Version: $ZLIB_VERSION
Libs: -L\${libdir} -lz
Libs.private: -lz
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
