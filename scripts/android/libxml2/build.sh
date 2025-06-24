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
LIBXML_VERSION="$3"

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
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBXML_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBXML_VERSION>"
        exit 1
    fi

    # Check that LIBXML_VERSION argument has been passed
    if [ -z "$LIBXML_VERSION" ]; then
        echo "Error: LIBXML_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <LIBXML_VERSION>"
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
    
    # Download libxml2 if not already present
    if [ ! -f "$DOWNLOAD_DIR/libxml2-$LIBXML_VERSION.tar.gz" ]; then
        echo "Downloading libxml2..."
        curl -L "https://github.com/GNOME/libxml2/archive/refs/tags/v$LIBXML_VERSION.tar.gz" -o "$DOWNLOAD_DIR/libxml2-$LIBXML_VERSION.tar.gz"
    fi

    # Extract libxml2 if not already extracted
    if [ ! -d "$BUILD_DIR/libxml2-$LIBXML_VERSION" ]; then
        echo "Extracting libxml2..."
        rm -rf "$BUILD_DIR/libxml2-$LIBXML_VERSION"
        tar xzf "$DOWNLOAD_DIR/libxml2-$LIBXML_VERSION.tar.gz" -C "$BUILD_DIR"
    fi
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    # Generate configure script
    if [ ! -f "$BUILD_DIR/libxml2-$LIBXML_VERSION/configure" ]; then
        echo "Generating configure script..."
        cd "$BUILD_DIR/libxml2-$LIBXML_VERSION"
        ./autogen.sh
        make distclean
        cd "$TARGET_DIR"
    fi

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
        "$BUILD_DIR/libxml2-$LIBXML_VERSION/configure" \
            --host="$HOST" \
            --prefix="$INSTALL_DIR/$ABI" \
            --enable-shared \
            --disable-static \
            --with-pic \
            --with-sysroot="$SYSROOT" \
            --without-python \
            --without-lzma \
            --without-zlib \
            --without-iconv \
            --without-icu \
            --without-iso8859x \
            --without-ftp \
            --without-http \
            --without-catalog \
            --without-docbook \
            --without-c14n \
            --without-schematron \
            --without-schemas \
            --without-xinclude \
            --without-xpath \
            --without-xptr \
            --without-modules \
            --without-debug \
            --without-mem-debug \
            --without-run-debug \
            --without-regexps \
            --without-coverage \
            --without-threads \
            --without-history \
            --without-readline \
            --without-pattern \
            --without-push \
            --without-valid \
            --without-writer \
            --without-sax1 \
            --without-legacy \
            CC="$CC" \
            CXX="$CXX" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            STRIP="$STRIP" \
            CFLAGS="-fPIC -O3 -fvisibility=hidden" \
            CXXFLAGS="-fPIC -O3 -fvisibility=hidden" \
            LDFLAGS="-fPIC"
        
        # Clean previous build
        make clean
        
        # Build only the library
        make libxml2.la
        
        # Install only the library and headers
        make install-libLTLIBRARIES install-data
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
    cat > "$INSTALL_DIR/libxml2-config.cmake" << EOF
set(LIBXML2_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(LIBXML2_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libxml2.a")
set(LIBXML2_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/libxml-2.0.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: libxml-2.0
Description: XML parser library
Version: $LIBXML_VERSION
Libs: -L\${libdir} -lxml2
Libs.private: -lm
Cflags: -I\${includedir}/libxml2
EOF

    echo "Installation completed successfully!"
    echo "CMake and pkg-config files are available in: $INSTALL_DIR" 

}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
