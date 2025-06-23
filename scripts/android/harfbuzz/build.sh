#!/bin/bash

# Exit on error
set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Define directories
BUILD_DIR="$SCRIPT_DIR/build"
DOWNLOAD_DIR="$SCRIPT_DIR/download"
INSTALL_DIR="$SCRIPT_DIR/install"

# Create directories if they don't exist
mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR" "$INSTALL_DIR"

# Ask for NDK path if not provided as argument
if [ -z "$1" ]; then
    echo "Please provide the path to your Android NDK (e.g., /path/to/android-sdk/ndk)"
    read -r NDK_BASE_DIR
else
    NDK_BASE_DIR="$1"
fi

# Check if NDK exists
if [ ! -d "$NDK_BASE_DIR" ]; then
    echo "Error: Android NDK directory not found at $NDK_BASE_DIR"
    echo "Please provide a valid path to the Android NDK directory"
    exit 1
fi

# Find the latest NDK version
NDK_DIR=""
# Get all version directories and sort them in reverse order (latest first)
versions=$(ls -1 "$NDK_BASE_DIR" | grep -E '^[0-9]+\.' | sort -rV)
if [ -n "$versions" ]; then
    latest_version=$(echo "$versions" | head -n1)
    NDK_DIR="$NDK_BASE_DIR/$latest_version"
    echo "Found NDK version: $latest_version"
else
    echo "Error: No NDK version found in $NDK_BASE_DIR"
    exit 1
fi

# Clone Harfbuzz if not already present
if [ ! -d "$BUILD_DIR/harfbuzz" ]; then
    echo "Cloning Harfbuzz..."
    git clone https://github.com/harfbuzz/harfbuzz.git "$BUILD_DIR/harfbuzz"
    cd "$BUILD_DIR/harfbuzz"
    git checkout main
fi

# Define architectures to build for
ARCHS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
API_LEVEL=21

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
    CC="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin/${HOST}${API_LEVEL}-clang"
    CXX="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin/${HOST}${API_LEVEL}-clang++"
    AR="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
    RANLIB="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ranlib"
    STRIP="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip"
    
    # Set up sysroot
    SYSROOT="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64/sysroot"
    
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
        -DHB_BUILD_SUBSET=OFF \
        -DBUILD_SHARED_LIBS=ON
    
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
set(HARFBUZZ_LIBRARIES "\${CMAKE_CURRENT_LIST_DIR}/lib/libharfbuzz.so")
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