#!/bin/bash

# Exit on error
set -e

# Convert TARGET_DIR to absolute path
TARGET_DIR="$(cd "$(dirname "$TARGET_DIR")" && pwd)/$(basename "$TARGET_DIR")"

NDK_DIR="$1"
PODOFO_WRAPPER_DIR="$2"
TARGET_DIR="$3"

# Define directories
INSTALL_DIR="$TARGET_DIR/install"
BUILD_DIR="$TARGET_DIR/build"
TEMP_DIR="$TARGET_DIR/temp_aar"
AAR_OUTPUT_DIR="$TARGET_DIR/output"
JAVA_SRC_DIR="$TARGET_DIR/src/main/java"
JAVA_CLASSES_DIR="$TEMP_DIR/classes"

# Check for NDK environment variable
if [ -z "$NDK_DIR" ]; then
    echo "Error: NDK_DIR environment variable is not set"
    echo "Please set it to your Android NDK location"
    exit 1
fi

# Set up NDK toolchain
TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"
API_LEVEL=21

# Create temporary and output directories
rm -rf "$AAR_OUTPUT_DIR"
mkdir -p "$AAR_OUTPUT_DIR" "$BUILD_DIR"

# Copy static libraries and headers for each architecture
ANDROID_ARCHS=("arm64-v8a" "x86" "x86_64")

for ABI in "${ANDROID_ARCHS[@]}"; do
    echo "Processing $ABI..."
    
    # Create architecture-specific directory
    mkdir -p "$BUILD_DIR/jni/$ABI" "$TEMP_DIR/jni/$ABI"
    
    # Set up compiler for this architecture
    case $ABI in
        "arm64-v8a")
            CC="$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang"
            CXX="$TOOLCHAIN/bin/aarch64-linux-android$API_LEVEL-clang++"
            ;;
        "x86")
            CC="$TOOLCHAIN/bin/i686-linux-android$API_LEVEL-clang"
            CXX="$TOOLCHAIN/bin/i686-linux-android$API_LEVEL-clang++"
            ;;
        "x86_64")
            CC="$TOOLCHAIN/bin/x86_64-linux-android$API_LEVEL-clang"
            CXX="$TOOLCHAIN/bin/x86_64-linux-android$API_LEVEL-clang++"
            ;;
    esac

    # Create shared library from static libraries
    echo "Creating shared library for $ABI..."
    "$CXX" -shared -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -o "$BUILD_DIR/jni/$ABI/libpodofo.so" \
        -I"$JAVA_HOME/include" \
        -I"$JAVA_HOME/include/linux" \
        -I"$PODOFO_WRAPPER_DIR" \
        -I"$INSTALL_DIR/$ABI/include" \
        -I"$INSTALL_DIR/$ABI/include/podofo" \
        -I"$INSTALL_DIR/$ABI/include/podofo/main" \
        -I"$INSTALL_DIR/$ABI/include/podofo/auxiliary" \
        -I"$INSTALL_DIR/$ABI/include/podofo/3rdparty" \
        -I"$INSTALL_DIR/$ABI/include/podofo/optional" \
        "$PODOFO_WRAPPER_DIR/podofo_jni.cpp" \
        -Wl,--whole-archive \
        "$INSTALL_DIR/$ABI/lib/libpodofo.a" \
        "$INSTALL_DIR/$ABI/lib/libpodofo_private.a" \
        "$INSTALL_DIR/$ABI/lib/libpodofo_3rdparty.a" \
        "$INSTALL_DIR/$ABI/lib/libbrotli.a" \
        "$INSTALL_DIR/$ABI/lib/libbrotlidec.a" \
        "$INSTALL_DIR/$ABI/lib/libbrotlienc.a" \
        "$INSTALL_DIR/$ABI/lib/libbz2.a" \
        "$INSTALL_DIR/$ABI/lib/libfreetype.a" \
        "$INSTALL_DIR/$ABI/lib/libharfbuzz.a" \
        "$INSTALL_DIR/$ABI/lib/libpng.a" \
        "$INSTALL_DIR/$ABI/lib/libxml2.a" \
        "$INSTALL_DIR/$ABI/lib/libssl.a" \
        "$INSTALL_DIR/$ABI/lib/libcrypto.a" \
        "$INSTALL_DIR/$ABI/lib/libz.a" \
        -Wl,--no-whole-archive \
        -llog

    # Copy C++ runtime library
    case $ABI in
        "arm64-v8a")
            cp "$TOOLCHAIN/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so" "$BUILD_DIR/jni/$ABI/"
            ;;
        "x86")
            cp "$TOOLCHAIN/sysroot/usr/lib/i686-linux-android/libc++_shared.so" "$BUILD_DIR/jni/$ABI/"
            ;;
        "x86_64")
            cp "$TOOLCHAIN/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so" "$BUILD_DIR/jni/$ABI/"
            ;;
    esac
    
    # Copy headers (only once, since they're the same for all architectures)
    if [ "$ABI" = "arm64-v8a" ]; then
        cp -r "$INSTALL_DIR/$ABI/include" "$BUILD_DIR/jni/"
    fi
done


# # Create AndroidManifest.xml
# cat > "$TEMP_DIR/AndroidManifest.xml" << EOF
# <?xml version="1.0" encoding="utf-8"?>
# <manifest xmlns:android="http://schemas.android.com/apk/res/android"
#     package="com.podofo.android">
#     <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
#     <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
# </manifest>
# EOF

# mkdir -p "$JAVA_CLASSES_DIR"

# # Compile Java class
# echo "Compiling Java class..."
# javac -source 1.8 -target 1.8 \
#     -cp "$ANDROID_HOME/platforms/android-33/android.jar" \
#     -d "$JAVA_CLASSES_DIR" \
#     "$JAVA_SRC_DIR/com/podofo/android/PoDoFoWrapper.java"

# # Create classes.jar with manifest
# echo "Creating classes.jar..."
# cat > "$TEMP_DIR/MANIFEST.MF" << EOF
# Manifest-Version: 1.0
# Created-By: PoDoFo Android Library
# EOF

# # Create classes.jar with proper directory structure
# cd "$JAVA_CLASSES_DIR"
# find . -name "*.class" | xargs jar cfm "$TEMP_DIR/classes.jar" "$TEMP_DIR/MANIFEST.MF"
# cd "$TARGET_DIR"

# # Create R.txt (empty since we don't have resources)
# touch "$TEMP_DIR/R.txt"

# # Package the AAR
# cd "$TEMP_DIR"
# zip -r "$AAR_OUTPUT_DIR/podofo-android.aar" AndroidManifest.xml classes.jar R.txt jni res libs

# # Clean up
# cd "$TARGET_DIR"
# rm -rf "$TEMP_DIR"

# echo "AAR file created successfully at: $AAR_OUTPUT_DIR/podofo-android.aar" 