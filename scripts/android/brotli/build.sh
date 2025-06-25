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
BROTLI_VERSION="$3"

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
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <BROTLI_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <BROTLI_VERSION>"
        exit 1
    fi

    # Check that BROTLI_VERSION argument has been passed
    if [ -z "$BROTLI_VERSION" ]; then
        echo "Error: BROTLI_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <BROTLI_VERSION>"
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

    # Download brotli if not already present
    if [ ! -f "$DOWNLOAD_DIR/$BROTLI_VERSION.tar.gz" ]; then
        echo "Downloading brotli..."
        curl -L "https://github.com/google/brotli/archive/refs/tags/v$BROTLI_VERSION.tar.gz" -o "$DOWNLOAD_DIR/brotli-$BROTLI_VERSION.tar.gz"
    fi

    # Extract brotli if not already extracted
    if [ ! -d "$BUILD_DIR/brotli-$BROTLI_VERSION" ]; then
        echo "Extracting brotli..."
        tar xzf "$DOWNLOAD_DIR/brotli-$BROTLI_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

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
        cp -r "$BUILD_DIR/brotli-$BROTLI_VERSION"/* .
        
        # Configure and build brotli
        mkdir -p out
        cd out
        
        # Create a custom toolchain file
        cat > android.toolchain.cmake << EOF
cmake_minimum_required(VERSION 3.10)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION $API_LEVEL)
set(CMAKE_ANDROID_ARCH_ABI $ABI)
set(CMAKE_ANDROID_NDK $NDK_DIR)
set(CMAKE_ANDROID_STL_TYPE c++_static)
set(CMAKE_C_COMPILER $CC)
set(CMAKE_CXX_COMPILER $CXX)
set(CMAKE_AR $AR)
set(CMAKE_RANLIB $RANLIB)
set(CMAKE_STRIP $STRIP)
set(CMAKE_FIND_ROOT_PATH $SYSROOT)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
        
        cmake .. \
            -DCMAKE_TOOLCHAIN_FILE=android.toolchain.cmake \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -DBROTLI_BUNDLED_MODE=ON \
            -DBROTLI_DISABLE_TESTS=ON \
            -DCMAKE_POLICY_DEFAULT_CMP0057=NEW
        
        make -j$(nproc)
        
        # Create install directory
        mkdir -p "$INSTALL_DIR/$ABI/lib" "$INSTALL_DIR/$ABI/include"
        
        # Install library and headers
        cp libbrotli*.a "$INSTALL_DIR/$ABI/lib/"
        cp -r ../c/include "$INSTALL_DIR/$ABI/"
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
    cat > "$INSTALL_DIR/brotli-config.cmake" << EOF
set(BROTLI_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(BROTLI_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libbrotli.so")
set(BROTLI_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/brotli.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: brotli
Description: Brotli compression library
Version: $BROTLI_VERSION
Libs: -L\${libdir} -lbrotli
Libs.private: -lbrotli
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
