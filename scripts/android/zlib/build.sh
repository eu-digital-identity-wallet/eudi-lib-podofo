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
    # Download zlib if not present
    if [ ! -d "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION" ]; then
        echo "Downloading zlib..."
        mkdir -p "$DOWNLOAD_DIR"
        cd "$DOWNLOAD_DIR"
        
        # Try multiple mirrors
        for URL in \
            "https://github.com/madler/zlib/archive/refs/tags/v$ZLIB_VERSION.tar.gz" \
            "https://zlib.net/zlib-$ZLIB_VERSION.tar.gz" \
            "https://www.zlib.net/zlib-$ZLIB_VERSION.tar.gz"
        do
            echo "Trying to download from $URL"
            if curl -L -o zlib-$ZLIB_VERSION.tar.gz "$URL" && [ -s zlib-$ZLIB_VERSION.tar.gz ]; then
                echo "Download successful"
                break
            fi
            echo "Download failed, trying next mirror..."
        done
        
        # Verify the downloaded file
        if [ ! -s zlib-$ZLIB_VERSION.tar.gz ]; then
            echo "Error: Failed to download zlib"
            exit 1
        fi
        
        echo "Extracting zlib..."
        tar xzf zlib-$ZLIB_VERSION.tar.gz
        if [ ! -d "zlib-$ZLIB_VERSION" ]; then
            echo "Error: Failed to extract zlib archive"
            exit 1
        fi
        cd ..
    fi
}

function build() {

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Build for each architecture
    for ABI in "${ARCHS[@]}"; do
        echo "Building for $ABI..."
        
        # Set up toolchain
        case "$ABI" in
            "arm64-v8a")
                TOOLCHAIN="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$API_LEVEL-clang"
                AR="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
                ;;
            "armeabi-v7a")
                TOOLCHAIN="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi$API_LEVEL-clang"
                AR="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
                ;;
            "x86")
                TOOLCHAIN="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android$API_LEVEL-clang"
                AR="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
                ;;
            "x86_64")
                TOOLCHAIN="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android$API_LEVEL-clang"
                AR="$NDK_DIR/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
                ;;
        esac

        # Create build directory
        BUILD_DIR_ARCH="$BUILD_DIR/$ABI"
        rm -rf "$BUILD_DIR_ARCH"
        mkdir -p "$BUILD_DIR_ARCH"
        cp -r "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION/"* "$BUILD_DIR_ARCH/"
        cd "$BUILD_DIR_ARCH"

        # Configure and build
        export CC="$TOOLCHAIN"
        export AR="$AR"
        export CFLAGS="-fPIC -O3"
        export LDFLAGS="-shared"
        
        ./configure --prefix="$INSTALL_DIR/$ABI"
        make clean
        
        # Build object files
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o adler32.o adler32.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o crc32.o crc32.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o deflate.o deflate.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o infback.o infback.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o inffast.o inffast.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o inflate.o inflate.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o inftrees.o inftrees.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o trees.o trees.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o zutil.o zutil.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o compress.o compress.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o uncompr.o uncompr.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o gzclose.o gzclose.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o gzlib.o gzlib.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o gzread.o gzread.c
        $CC $CFLAGS -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN -I. -c -o gzwrite.o gzwrite.c
        
        # Create shared library
        $CC -shared -Wl,-soname,libz.so.1 -o libz.so.$ZLIB_VERSION *.o
        ln -sf libz.so.$ZLIB_VERSION libz.so.1
        ln -sf libz.so.1 libz.so
        
        # Install
        mkdir -p "$INSTALL_DIR/$ABI/lib" "$INSTALL_DIR/$ABI/include"
        cp libz.so* "$INSTALL_DIR/$ABI/lib/"
        cp zlib.h zconf.h "$INSTALL_DIR/$ABI/include/"
        
        # Create CMake config
        mkdir -p "$INSTALL_DIR/$ABI/lib/cmake/zlib"
        cat > "$INSTALL_DIR/$ABI/lib/cmake/zlib/zlib-config.cmake" << EOF
set(ZLIB_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/../../include")
set(ZLIB_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/libz.so")
EOF

        # Create pkg-config file
        mkdir -p "$INSTALL_DIR/$ABI/lib/pkgconfig"
        cat > "$INSTALL_DIR/$ABI/lib/pkgconfig/zlib.pc" << EOF
prefix=$INSTALL_DIR/$ABI
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
sharedlibdir=\${libdir}
includedir=\${prefix}/include

Name: zlib
Description: zlib compression library
Version: $ZLIB_VERSION

Requires:
Libs: -L\${libdir} -L\${sharedlibdir} -lz
Cflags: -I\${includedir}
EOF

        cd ../..
    done

    echo "Build completed. Libraries installed in $INSTALL_DIR"
}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
