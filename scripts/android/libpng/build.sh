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
LIBPNG_VERSION="$3"

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
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBPNG_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBPNG_VERSION>"
        exit 1
    fi

    # Check that LIBPNG_VERSION argument has been passed
    if [ -z "$LIBPNG_VERSION" ]; then
        echo "Error: LIBPNG_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBPNG_VERSION>"
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

    # Download libpng if not already present
    if [ ! -f "$DOWNLOAD_DIR/libpng-$LIBPNG_VERSION.tar.gz" ]; then
        echo "Downloading libpng..."
        curl -L "https://downloads.sourceforge.net/project/libpng/libpng16/$LIBPNG_VERSION/libpng-$LIBPNG_VERSION.tar.gz" -o "$DOWNLOAD_DIR/libpng-$LIBPNG_VERSION.tar.gz"
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
        
        # Configure build
        "$BUILD_DIR/libpng-$LIBPNG_VERSION/configure" \
            --host="$HOST" \
            --prefix="$INSTALL_DIR/$ABI" \
            --disable-static \
            --enable-shared \
            --with-pic \
            --with-sysroot="$SYSROOT" \
            --disable-tools \
            --disable-tests \
            CC="$CC" \
            CXX="$CXX" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            STRIP="$STRIP" \
            CFLAGS="-fPIC -O3 -fvisibility=hidden -DPNG_INTEL_SSE_OPT=0" \
            CXXFLAGS="-fPIC -O3 -fvisibility=hidden -DPNG_INTEL_SSE_OPT=0" \
            LDFLAGS="-fPIC"
        
        # Clean previous build
        make clean
        
        # Build the shared library
        make
        
        # Install library and headers
        make install
        
        # Create symlink for libpng.so
        cd "$INSTALL_DIR/$ABI/lib"
        ln -sf libpng16.so libpng.so
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
    cat > "$INSTALL_DIR/libpng-config.cmake" << EOF
set(LIBPNG_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(LIBPNG_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libpng16.so")
set(LIBPNG_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/libpng.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: libpng
Description: Loads and saves PNG files
Version: $LIBPNG_VERSION
Libs: -L\${libdir} -lpng16 -lz -lm
Libs.private: -lz -lm
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
