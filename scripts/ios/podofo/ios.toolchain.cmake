# This file is based on the iOS cmake toolchain file from https://github.com/leetal/ios-cmake
# Simplified for our specific use case

# This is a basic version of the iOS toolchain file
# It sets up the environment for cross-compiling to iOS

# Supported architectures: armv7, armv7s, arm64, i386, x86_64
# Supported platforms: iphoneos, iphonesimulator

# Options:
# PLATFORM: (default "iphoneos")
#    OS = iphoneos
#    SIMULATOR = iphonesimulator
#
# DEPLOYMENT_TARGET: (default 16.5)
#    The minimum iOS version to target
#
# ARCHS: (default "$(ARCHS_STANDARD)")
#    The architecture to build for

# Standard settings
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR arm64)
set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)
set(DEPLOYMENT_TARGET "16.5")

# Get the Xcode version
execute_process(COMMAND xcodebuild -version
  OUTPUT_VARIABLE XCODE_VERSION
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "Xcode [0-9\\.]+" XCODE_VERSION "${XCODE_VERSION}")
string(REGEX REPLACE "Xcode ([0-9\\.]+)" "\\1" XCODE_VERSION "${XCODE_VERSION}")

# Default to iphoneos if not specified
if(NOT DEFINED PLATFORM)
  set(PLATFORM "iphoneos")
endif()

# Get platform display name
if(PLATFORM STREQUAL "iphoneos")
  set(PLATFORM_DISPLAY_NAME "iOS")
  set(CMAKE_SYSTEM_PROCESSOR "arm64")
elseif(PLATFORM STREQUAL "iphonesimulator")
  set(PLATFORM_DISPLAY_NAME "iOS Simulator")
  set(CMAKE_SYSTEM_PROCESSOR "x86_64")
else()
  message(FATAL_ERROR "Unsupported PLATFORM: ${PLATFORM}")
endif()

# Get SDK path
execute_process(COMMAND xcrun --sdk ${PLATFORM} --show-sdk-path
  OUTPUT_VARIABLE SDK_PATH
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE)

if(NOT EXISTS ${SDK_PATH})
  message(FATAL_ERROR "iOS SDK not found at: ${SDK_PATH}")
endif()

# Set architectures
if(NOT DEFINED ARCHS)
  if(PLATFORM STREQUAL "iphoneos")
    set(ARCHS "arm64")
  else()
    set(ARCHS "x86_64;arm64")
  endif()
endif()

# Set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fembed-bitcode-marker -fobjc-abi-version=2 -fobjc-arc")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fembed-bitcode-marker -fobjc-abi-version=2 -fobjc-arc")

# Set SDK and deployment target flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isysroot ${SDK_PATH} -m${PLATFORM}-version-min=${DEPLOYMENT_TARGET}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isysroot ${SDK_PATH} -m${PLATFORM}-version-min=${DEPLOYMENT_TARGET}")

# Set linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -isysroot ${SDK_PATH}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -isysroot ${SDK_PATH}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -isysroot ${SDK_PATH}")

# Set the find root path
set(CMAKE_FIND_ROOT_PATH ${SDK_PATH})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Set the executable suffix
set(CMAKE_EXECUTABLE_SUFFIX ".app")

# Set the framework and bundle stuff
set(CMAKE_MACOSX_BUNDLE YES)
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "")

# Output settings
message(STATUS "Configuring for platform: ${PLATFORM_DISPLAY_NAME}")
message(STATUS "Using SDK: ${SDK_PATH}")
message(STATUS "Using deployment target: ${DEPLOYMENT_TARGET}")
message(STATUS "Using architectures: ${ARCHS}") 