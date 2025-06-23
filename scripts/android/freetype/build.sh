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
FREETYPE_VERSION="$3"
BZIP2_DIR="$4"
BROTLI_DIR="$5"

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
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <FREETYPE_VERSION> <BZIP2_DIR> <BROTLI_DIR>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <FREETYPE_VERSION> <BZIP2_DIR> <BROTLI_DIR>"
        exit 1
    fi

    # Check that FREETYPE_VERSION argument has been passed
    if [ -z "$FREETYPE_VERSION" ]; then
        echo "Error: FREETYPE_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <FREETYPE_VERSION> <BZIP2_DIR> <BROTLI_DIR>"
        exit 1
    fi

    # Check if NDK exists
    if [ ! -d "$NDK_DIR" ]; then
        echo "Error: Android NDK directory not found at $NDK_DIR"
        echo "Please provide a valid path to the Android NDK directory"
        exit 1
    fi
    
    # Check if BZIP_DIR exists
    if [ -z "$BZIP2_DIR" ]; then
        echo "Error: BZIP2_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <FREETYPE_VERSION> <BZIP2_DIR> <BROTLI_DIR>"
        exit 1
    elif [ ! -d "$BZIP2_DIR" ]; then
        echo "Error: BZIP2_DIR directory not found at $BZIP2_DIR"
        echo "Please provide a valid path to the BZIP2 directory"
        exit 1
    fi

    # Check if BROTLI_DIR exists
    if [ -z "$BROTLI_DIR" ]; then
        echo "Error: BROTLI_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <FREETYPE_VERSION> <BZIP2_DIR> <BROTLI_DIR>"
        exit 1
    elif [ ! -d "$BROTLI_DIR" ]; then
        echo "Error: BROTLI_DIR directory not found at $BROTLI_DIR"
        echo "Please provide a valid path to the BROTLI directory"
        exit 1
    fi
}

function prepare() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"

    # Download freetype if not already present
    if [ ! -f "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz" ]; then
        echo "Downloading freetype..."
        curl -L "https://download.savannah.gnu.org/releases/freetype/freetype-$FREETYPE_VERSION.tar.gz" -o "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz"
    fi

    # Extract freetype if not already extracted
    if [ ! -d "$BUILD_DIR/freetype-$FREETYPE_VERSION" ]; then
        echo "Extracting freetype..."
        tar xzf "$DOWNLOAD_DIR/freetype-$FREETYPE_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    # Build for each architecture
    for ABI in "${ARCHS[@]}"; do
        echo "Building for $ABI..."
        
        # Set up Android toolchain
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
        TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"
        CC="$TOOLCHAIN/bin/${HOST}${API_LEVEL}-clang"
        CXX="$TOOLCHAIN/bin/${HOST}${API_LEVEL}-clang++"
        AR="$TOOLCHAIN/bin/llvm-ar"
        RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
        STRIP="$TOOLCHAIN/bin/llvm-strip"
        
        # Set up sysroot
        SYSROOT="$TOOLCHAIN/sysroot"
        
        # Create build directory for this architecture
        ARCH_BUILD_DIR="$BUILD_DIR/$ABI"
        mkdir -p "$ARCH_BUILD_DIR"
        cd "$ARCH_BUILD_DIR"
        
        # Set up environment variables for cross-compilation
        export CC
        export CXX
        export AR
        export RANLIB
        export STRIP
        export CFLAGS="-fPIC -O3 -fvisibility=hidden -I$BZIP2_DIR/include -I$BROTLI_DIR/$ABI/include"
        export CXXFLAGS="-fPIC -O3 -fvisibility=hidden -I$BZIP2_DIR/include -I$BROTLI_DIR/$ABI/include"
        export LDFLAGS="-fPIC -L$BZIP2_DIR/lib -L$BROTLI_DIR/$ABI/lib"
        
        # Configure and build freetype
        "$BUILD_DIR/freetype-$FREETYPE_VERSION/configure" \
            --host="$HOST" \
            --prefix="$INSTALL_DIR/$ABI" \
            --enable-shared \
            --disable-static \
            --with-png="no" \
            --with-sysroot="$SYSROOT" \
            --with-bzip2="$BZIP2_DIR" \
            --with-brotli="$BROTLI_DIR/$ABI" \
            LDFLAGS="-L$BROTLI_DIR/$ABI/lib -lbrotlidec -lbrotlienc -lbrotlicommon"
        
        # Clean previous build
        make clean
        
        # Build and install
        make install
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create CMake configuration files
    echo "Creating CMake configurations..."

    # freetype CMake config
    cat > "$INSTALL_DIR/freetype-config.cmake" << EOF
set(FREETYPE_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(FREETYPE_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libfreetype.so")
set(FREETYPE_FOUND TRUE)
EOF

    # Create pkg-config files
    echo "Creating pkg-config files..."

    # freetype pkg-config
    cat > "$INSTALL_DIR/freetype2.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: FreeType 2
Description: A free, high-quality, and portable font engine
Version: $FREETYPE_VERSION
Libs: -L\${libdir} -lfreetype -lz -lm -lbrotlidec -lbrotlienc -lbrotlicommon
Libs.private: -lz -lm -lbrotlidec -lbrotlienc -lbrotlicommon
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
