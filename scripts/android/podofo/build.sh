#!/bin/bash

# Exit on error
set -e

# PoDoFo Configuration
PODOFO_VERSION="master"
PODOFO_REPO_NAME="EUDI_PoDoFo"

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
FREETYPE_DIR="$3"
LIBPNG_DIR="$4"
LIBXML2_DIR="$5"
OPENSSL_DIR="$6"

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
        echo "Usage: $0 <NDK_DIR> <FREETYPE_DIR> <LIBPNG_DIR> <LIBXML2_DIR> <OPENSSL_DIR>"
        exit 1
    fi

}

function prepare() {
    # Clean up existing build directory
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"/podofo/

    # Exclude the build directory itself from being copied
    rsync -a --exclude 'build' ./ "$BUILD_DIR"/podofo/
}

function build() {
    # Create directories if they don't exist
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

    echo "Fixing XML_SAVE constants..."
    sed -i 's/XML_SAVE_NO_DECL | XML_SAVE_FORMAT/(int)(XML_SAVE_NO_DECL | XML_SAVE_FORMAT)/' "$BUILD_DIR/podofo/src/podofo/main/PdfXMPPacket.cpp"

    echo "Configuring PoDoFo..."

    # Build for each architecture
    for ABI in "${ARCHS[@]}"; do
        echo "Building for $ABI..."
        
        # Create build directory for this architecture
        ARCH_BUILD_DIR="$BUILD_DIR/$ABI"
        mkdir -p "$ARCH_BUILD_DIR"
        cd "$ARCH_BUILD_DIR"
        
        # Configure and build PoDoFo
        cmake "$BUILD_DIR/podofo" \
            -DCMAKE_TOOLCHAIN_FILE="$NDK_DIR/build/cmake/android.toolchain.cmake" \
            -DANDROID_ABI="$ABI" \
            -DANDROID_PLATFORM=android-${API_LEVEL} \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR/$ABI" \
            -DFREETYPE_INCLUDE_DIRS="$FREETYPE_DIR/$ABI/include/freetype2" \
            -DFREETYPE_LIBRARY="$FREETYPE_DIR/$ABI/lib/libfreetype.a" \
            -DPNG_PNG_INCLUDE_DIR="$LIBPNG_DIR/$ABI/include" \
            -DPNG_LIBRARY="$LIBPNG_DIR/$ABI/lib/libpng.a" \
            -DLIBXML2_INCLUDE_DIR="$LIBXML2_DIR/$ABI/include/libxml2" \
            -DLIBXML2_LIBRARY="$LIBXML2_DIR/$ABI/lib/libxml2.a" \
            -DOPENSSL_ROOT_DIR="$OPENSSL_DIR/$ABI" \
            -DOPENSSL_INCLUDE_DIR="$OPENSSL_DIR/$ABI/include" \
            -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_DIR/$ABI/lib/libcrypto.a" \
            -DOPENSSL_SSL_LIBRARY="$OPENSSL_DIR/$ABI/lib/libssl.a" \
            -DPODOFO_BUILD_STATIC=ON \
            -DPODOFO_BUILD_TOOLS=OFF \
            -DPODOFO_BUILD_EXAMPLES=OFF \
            -DPODOFO_BUILD_DOC=OFF \
            -DPODOFO_BUILD_TEST=OFF \
            -DPODOFO_NO_FONTCONFIG=ON \
            -DPODOFO_NO_WIN32GRAPHICS=ON \
            -DPODOFO_NO_X11=ON \
            -DCMAKE_CXX_FLAGS="-I$LIBXML2_DIR/$ABI/include -I$FREETYPE_DIR/$ABI/include -I$LIBPNG_DIR/$ABI/include -I$OPENSSL_DIR/$ABI/include"
        
        # Build and install
        make install
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create CMake configuration files
    echo "Creating CMake configurations..."

    # PoDoFo CMake config
    cat > "$INSTALL_DIR/podofo-config.cmake" << EOF
set(PODOFO_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(PODOFO_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libpodofo.a")
set(PODOFO_FOUND TRUE)
EOF

    # Create pkg-config files
    echo "Creating pkg-config files..."

    # PoDoFo pkg-config
    cat > "$INSTALL_DIR/libpodofo.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: PoDoFo
Description: PDF parsing, modification and creation library
Version: 0.9.8
Libs: -L\${libdir} -lpodofo -lfreetype -lpng -lxml2 -lssl -lcrypto -lz -lm
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
