#!/bin/bash

# Script to build FreeType for iOS as a framework
# Supports both device (arm64) and simulator (x86_64 and arm64)

set -e

# Configuration
FREETYPE_VERSION="2.13.3"

# Download and extract freetype if not already present
if [ ! -d "freetype-${FREETYPE_VERSION}" ]; then
    echo "Downloading freetype-${FREETYPE_VERSION}..."
    curl -L "https://download.savannah.gnu.org/releases/freetype/freetype-${FREETYPE_VERSION}.tar.gz" -o "freetype-${FREETYPE_VERSION}.tar.gz"
    tar -xzf "freetype-${FREETYPE_VERSION}.tar.gz"
fi

cd "freetype-${FREETYPE_VERSION}"

# Configuration
FREETYPE_VERSION=$(grep -m 1 "FREETYPE_VERSION" include/freetype/freetype.h | awk '{print $3}' | tr -d '"')
if [ -z "$FREETYPE_VERSION" ]; then
    FREETYPE_VERSION="2.13.3"  # Default version if not found
fi
FRAMEWORK_NAME="FreeType"
FRAMEWORK_VERSION="A"
FRAMEWORK_CURRENT_VERSION="$FREETYPE_VERSION"
FRAMEWORK_COMPATIBILITY_VERSION="$FREETYPE_VERSION"

# Paths
DEVELOPER=$(xcode-select -print-path)
BUILD_DIR="$(pwd)/build/ios"
FRAMEWORK_DIR="${BUILD_DIR}/${FRAMEWORK_NAME}.framework"
SRCDIR=$(pwd)

# iOS SDK version
MIN_IOS_VERSION="11.0"

# Architectures
ARCH_DEVICE="arm64"
ARCH_SIMULATOR_INTEL="x86_64"
ARCH_SIMULATOR_ARM="arm64"

# Clean previous builds
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "Building FreeType version ${FREETYPE_VERSION} for iOS"

build_for_architecture() {
    local ARCH=$1
    local PLATFORM=$2
    local SDK=$3
    local BUILD_PATH="${BUILD_DIR}/${ARCH}_${PLATFORM}"
    
    echo "Building for ${ARCH} (${PLATFORM})"
    
    mkdir -p "${BUILD_PATH}"
    
    # Get SDK path
    SDK_PATH=$(xcrun --sdk ${SDK} --show-sdk-path)
    
    # Configure and build with CMake
    cd "${BUILD_PATH}"
    
    # CMake toolchain file for iOS
    cat > "${BUILD_PATH}/ios.toolchain.cmake" << EOF
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_ARCHITECTURES ${ARCH})
set(CMAKE_OSX_SYSROOT ${SDK_PATH})
set(CMAKE_OSX_DEPLOYMENT_TARGET ${MIN_IOS_VERSION})
set(CMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH NO)
set(CMAKE_IOS_INSTALL_COMBINED NO)
set(CMAKE_FIND_ROOT_PATH ${SDK_PATH})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS "-arch ${ARCH} -fembed-bitcode")
set(CMAKE_CXX_FLAGS "-arch ${ARCH} -fembed-bitcode")
EOF
    
    # Run CMake
    cmake "${SRCDIR}" \
        -DCMAKE_TOOLCHAIN_FILE="${BUILD_PATH}/ios.toolchain.cmake" \
        -DCMAKE_INSTALL_PREFIX="${BUILD_PATH}/install" \
        -DBUILD_SHARED_LIBS=OFF \
        -DFT_WITH_ZLIB=OFF \
        -DFT_WITH_BZIP2=OFF \
        -DFT_WITH_PNG=OFF \
        -DFT_WITH_HARFBUZZ=OFF \
        -DCMAKE_BUILD_TYPE=Release
    
    # Build
    cmake --build . --config Release
    cmake --install . --config Release
    
    cd "${SRCDIR}"
}

# Build for device
build_for_architecture "${ARCH_DEVICE}" "iPhoneOS" "iphoneos"

# Build for Intel simulator
build_for_architecture "${ARCH_SIMULATOR_INTEL}" "iPhoneSimulator" "iphonesimulator"

# Build for Apple Silicon simulator
build_for_architecture "${ARCH_SIMULATOR_ARM}" "iPhoneSimulator" "iphonesimulator"

# Verify architectures
echo "Verifying architectures of built libraries..."
lipo -info "${BUILD_DIR}/${ARCH_DEVICE}_iPhoneOS/install/lib/libfreetype.a"
lipo -info "${BUILD_DIR}/${ARCH_SIMULATOR_INTEL}_iPhoneSimulator/install/lib/libfreetype.a"
lipo -info "${BUILD_DIR}/${ARCH_SIMULATOR_ARM}_iPhoneSimulator/install/lib/libfreetype.a"

# Create framework structure
mkdir -p "${FRAMEWORK_DIR}/Headers"
mkdir -p "${FRAMEWORK_DIR}/Modules"

# Create module map
cat > "${FRAMEWORK_DIR}/Modules/module.modulemap" << EOF
framework module ${FRAMEWORK_NAME} {
  umbrella header "${FRAMEWORK_NAME}.h"
  export *
  module * { export * }
}
EOF

# Create umbrella header
cat > "${FRAMEWORK_DIR}/Headers/${FRAMEWORK_NAME}.h" << EOF
#import <Foundation/Foundation.h>

// FreeType headers
#import "ft2build.h"
#import "freetype/freetype.h"
#import "freetype/ftadvanc.h"
#import "freetype/ftbbox.h"
#import "freetype/ftbdf.h"
#import "freetype/ftbitmap.h"
#import "freetype/ftbzip2.h"
#import "freetype/ftcache.h"
#import "freetype/ftchapters.h"
#import "freetype/ftcid.h"
#import "freetype/ftcolor.h"
#import "freetype/ftdriver.h"
#import "freetype/fterrdef.h"
#import "freetype/fterrors.h"
#import "freetype/ftfntfmt.h"
#import "freetype/ftgasp.h"
#import "freetype/ftglyph.h"
#import "freetype/ftgxval.h"
#import "freetype/ftgzip.h"
#import "freetype/ftimage.h"
#import "freetype/ftincrem.h"
#import "freetype/ftlcdfil.h"
#import "freetype/ftlist.h"
#import "freetype/ftlzw.h"
#import "freetype/ftmac.h"
#import "freetype/ftmm.h"
#import "freetype/ftmodapi.h"
#import "freetype/ftmoderr.h"
#import "freetype/ftotval.h"
#import "freetype/ftoutln.h"
#import "freetype/ftparams.h"
#import "freetype/ftpfr.h"
#import "freetype/ftrender.h"
#import "freetype/ftsizes.h"
#import "freetype/ftsnames.h"
#import "freetype/ftstroke.h"
#import "freetype/ftsynth.h"
#import "freetype/ftsystem.h"
#import "freetype/fttrigon.h"
#import "freetype/fttypes.h"
#import "freetype/ftwinfnt.h"
#import "freetype/t1tables.h"
#import "freetype/ttnameid.h"
#import "freetype/tttables.h"
#import "freetype/tttags.h"

FOUNDATION_EXPORT double ${FRAMEWORK_NAME}VersionNumber;
FOUNDATION_EXPORT const unsigned char ${FRAMEWORK_NAME}VersionString[];
EOF

# Copy headers
cp -R "${BUILD_DIR}/${ARCH_DEVICE}_iPhoneOS/install/include/freetype2/ft2build.h" "${FRAMEWORK_DIR}/Headers/"
cp -R "${BUILD_DIR}/${ARCH_DEVICE}_iPhoneOS/install/include/freetype2/freetype" "${FRAMEWORK_DIR}/Headers/"

# Create Info.plist
cat > "${FRAMEWORK_DIR}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>English</string>
	<key>CFBundleExecutable</key>
	<string>${FRAMEWORK_NAME}</string>
	<key>CFBundleIdentifier</key>
	<string>org.freetype.${FRAMEWORK_NAME}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${FRAMEWORK_NAME}</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>${FRAMEWORK_CURRENT_VERSION}</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleVersion</key>
	<string>${FRAMEWORK_CURRENT_VERSION}</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>iPhoneOS</string>
		<string>iPhoneSimulator</string>
	</array>
	<key>MinimumOSVersion</key>
	<string>${MIN_IOS_VERSION}</string>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
		<integer>2</integer>
	</array>
</dict>
</plist>
EOF

# Create separate libraries for device and simulator
# First, create a simulator library with both x86_64 and arm64 architectures
mkdir -p "${BUILD_DIR}/simulator_libs"
lipo -create \
    "${BUILD_DIR}/${ARCH_SIMULATOR_INTEL}_iPhoneSimulator/install/lib/libfreetype.a" \
    "${BUILD_DIR}/${ARCH_SIMULATOR_ARM}_iPhoneSimulator/install/lib/libfreetype.a" \
    -output "${BUILD_DIR}/simulator_libs/libfreetype_simulator.a"

# Now create the XCFramework
mkdir -p "${BUILD_DIR}/xcframework"
xcodebuild -create-xcframework \
    -library "${BUILD_DIR}/${ARCH_DEVICE}_iPhoneOS/install/lib/libfreetype.a" -headers "${FRAMEWORK_DIR}/Headers" \
    -library "${BUILD_DIR}/simulator_libs/libfreetype_simulator.a" -headers "${FRAMEWORK_DIR}/Headers" \
    -output "${BUILD_DIR}/xcframework/${FRAMEWORK_NAME}.xcframework"

# For backward compatibility, also create a fat binary for the framework
# We need to use a different approach since lipo can't handle same architecture for different platforms
# Extract all object files
mkdir -p "${BUILD_DIR}/temp_objs"
cd "${BUILD_DIR}/temp_objs"

# Extract object files from device library
mkdir -p device_objs
cd device_objs
ar -x "${BUILD_DIR}/${ARCH_DEVICE}_iPhoneOS/install/lib/libfreetype.a"
for file in *.o; do
    mv "$file" "../${ARCH_DEVICE}_${file}"
done
cd ..

# Extract object files from x86_64 simulator library
mkdir -p x86_64_sim_objs
cd x86_64_sim_objs
ar -x "${BUILD_DIR}/${ARCH_SIMULATOR_INTEL}_iPhoneSimulator/install/lib/libfreetype.a"
for file in *.o; do
    mv "$file" "../${ARCH_SIMULATOR_INTEL}_${file}"
done
cd ..

# Extract object files from arm64 simulator library
mkdir -p arm64_sim_objs
cd arm64_sim_objs
ar -x "${BUILD_DIR}/${ARCH_SIMULATOR_ARM}_iPhoneSimulator/install/lib/libfreetype.a"
for file in *.o; do
    # Rename to avoid conflicts with device arm64 objects
    mv "$file" "../${ARCH_SIMULATOR_ARM}_sim_${file}"
done
cd ..

# Create version files for all architectures
VERSION_NUM=$(echo "${FRAMEWORK_CURRENT_VERSION}" | tr -d '.')

# For device arm64
echo "const unsigned char ${FRAMEWORK_NAME}VersionString[] = \"${FRAMEWORK_CURRENT_VERSION}\";" > "${BUILD_DIR}/version_arm64_device.c"
echo "double ${FRAMEWORK_NAME}VersionNumber = ${VERSION_NUM:-213};" >> "${BUILD_DIR}/version_arm64_device.c"
xcrun -sdk iphoneos clang -arch arm64 -c "${BUILD_DIR}/version_arm64_device.c" -o "${BUILD_DIR}/temp_objs/${ARCH_DEVICE}_version.o"

# For simulator x86_64
echo "const unsigned char ${FRAMEWORK_NAME}VersionString[] = \"${FRAMEWORK_CURRENT_VERSION}\";" > "${BUILD_DIR}/version_x86_64_sim.c"
echo "double ${FRAMEWORK_NAME}VersionNumber = ${VERSION_NUM:-213};" >> "${BUILD_DIR}/version_x86_64_sim.c"
xcrun -sdk iphonesimulator clang -arch x86_64 -c "${BUILD_DIR}/version_x86_64_sim.c" -o "${BUILD_DIR}/temp_objs/${ARCH_SIMULATOR_INTEL}_version.o"

# For simulator arm64
echo "const unsigned char ${FRAMEWORK_NAME}VersionString[] = \"${FRAMEWORK_CURRENT_VERSION}\";" > "${BUILD_DIR}/version_arm64_sim.c"
echo "double ${FRAMEWORK_NAME}VersionNumber = ${VERSION_NUM:-213};" >> "${BUILD_DIR}/version_arm64_sim.c"
xcrun -sdk iphonesimulator clang -arch arm64 -c "${BUILD_DIR}/version_arm64_sim.c" -o "${BUILD_DIR}/temp_objs/${ARCH_SIMULATOR_ARM}_sim_version.o"

# Create the framework binary
libtool -static -o "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}" ${BUILD_DIR}/temp_objs/*.o

cd "${SRCDIR}"

# Make the framework shared library publicly readable
chmod 644 "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}"

echo "Framework successfully created at: ${FRAMEWORK_DIR}"
echo "XCFramework successfully created at: ${BUILD_DIR}/xcframework/${FRAMEWORK_NAME}.xcframework"
echo "Architectures in framework:"
lipo -info "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}"
echo "You can now copy this framework to your project." 