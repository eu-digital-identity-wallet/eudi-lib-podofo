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
HARFBUZZ_VERSION="$3"

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
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <HARFBUZZ_VERSION>"
        exit 1
    fi

    # Check that TARGET_DIR argument has been passed
    if [ -z "$TARGET_DIR" ]; then
        echo "Error: TARGET_DIR argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <HARFBUZZ_VERSION>"
        exit 1
    fi

    # Check that HARFBUZZ_VERSION argument has been passed
    if [ -z "$HARFBUZZ_VERSION" ]; then
        echo "Error: HARFBUZZ_VERSION argument not provided."
        echo "Usage: $0 <NDK_DIR> <TARGET_DIR> <HARFBUZZ_VERSION>"
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

    # Clone Harfbuzz if not already present
    if [ ! -d "$BUILD_DIR/harfbuzz" ]; then
        echo "Cloning Harfbuzz..."
        git clone https://github.com/harfbuzz/harfbuzz.git "$BUILD_DIR/harfbuzz"
        cd "$BUILD_DIR/harfbuzz"
        git checkout main
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
        ARCH_BUILD_DIR="$BUILD_DIR/harfbuzz-$ABI"
        mkdir -p "$ARCH_BUILD_DIR"
        cd "$ARCH_BUILD_DIR"
        
        # Configure Harfbuzz
        cmake "$BUILD_DIR/harfbuzz" \
            -DCMAKE_TOOLCHAIN_FILE="$NDK_DIR/build/cmake/android.toolchain.cmake" \
            -DANDROID_ABI="$ABI" \
            -DANDROID_PLATFORM="android-$API_LEVEL" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR/$ABI" \
            -DHB_HAVE_FREETYPE=OFF \
            -DHB_HAVE_GLIB=OFF \
            -DHB_HAVE_ICU=OFF \
            -DHB_BUILD_TESTS=OFF \
            -DHB_BUILD_UTILS=OFF \
            -DHB_BUILD_SUBSET=OFF
        
        # Build and install
        make -j$(nproc)
        make install
        
        echo "Build completed for $ABI"
    done

    echo "Build completed successfully!"
    echo "Libraries are installed in: $INSTALL_DIR"

    # Create a CMake configuration file
    echo "Creating CMake configuration..."
    cat > "$INSTALL_DIR/harfbuzz-config.cmake" << EOF
set(HARFBUZZ_INCLUDE_DIRS "\${CMAKE_CURRENT_LIST_DIR}/include")
set(HARFBUZZ_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libharfbuzz.a")
set(HARFBUZZ_FOUND TRUE)
EOF

    # Create a pkg-config file
    echo "Creating pkg-config file..."
    cat > "$INSTALL_DIR/harfbuzz.pc" << EOF
prefix=$INSTALL_DIR
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: harfbuzz
Description: HarfBuzz text shaping library
Version: $(git -C "$BUILD_DIR/harfbuzz" describe --tags --always)
Libs: -L\${libdir} -lharfbuzz
Libs.private: -lharfbuzz
Cflags: -I\${includedir}/harfbuzz
EOF

    echo "Installation completed successfully!"
    echo "CMake and pkg-config files are available in: $INSTALL_DIR"
}

check

if [ "$SKIP_PREPARE" -eq 0 ]; then
    prepare
fi

build
