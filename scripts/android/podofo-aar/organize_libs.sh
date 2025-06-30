#!/bin/bash

# Exit on error
set -e

# Check if all 9 parameters are provided
if [ $# -ne 10 ]; then
  echo "Error: Incorrect number of arguments"
  echo "Usage: $0 <brotli_path> <bzip2_path> <freetype_path> <harfbuzz_path> <libpng_path> <libxml2_path> <openssl_path> <podofo_path> <zlib_path> <target_path>"
  echo "Example: $0 ../brotli ../bzip2 ../freetype ../harfbuzz ../libpng ../libxml2 ../openssl ../podofo ../zlib ../install"
  exit 1
fi

if [ -z "$1" ]; then
  echo "Please provide the path to your Brotli folder (e.g., ../brotli)"
  read -r BROTLI_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$BROTLI_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    BROTLI_BASE_DIR="$1"
fi

if [ -z "$2" ]; then
  echo "Please provide the path to your bzip2 folder (e.g., ../bzip2)"
  read -r BZIP2_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$BZIP2_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    BZIP2_BASE_DIR="$2"
fi

if [ -z "$3" ]; then
  echo "Please provide the path to your freetype folder (e.g., ../freetype)"
  read -r FREETYPE_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$FREETYPE_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    FREETYPE_BASE_DIR="$3"
fi

if [ -z "$4" ]; then
  echo "Please provide the path to your harfbuzz folder (e.g., ../harfbuzz)"
  read -r HARFBUZZ_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$HARFBUZZ_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    HARFBUZZ_BASE_DIR="$4"
fi

if [ -z "$5" ]; then
  echo "Please provide the path to your libpng folder (e.g., ../libpng)"
  read -r LIBPNG_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$LIBPNG_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    LIBPNG_BASE_DIR="$5"
fi

if [ -z "$6" ]; then
  echo "Please provide the path to your libxml2 folder (e.g., ../libxml2)"
  read -r LIBXML2_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$LIBXML2_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    LIBXML2_BASE_DIR="$6"
fi

if [ -z "$7" ]; then
  echo "Please provide the path to your openssl folder (e.g., ../openssl)"
  read -r OPENSSL_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$OPENSSL_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    OPENSSL_BASE_DIR="$7"
fi

if [ -z "$8" ]; then
  echo "Please provide the path to your podofo folder (e.g., ../podofo)"
  read -r PODOFO_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$PODOFO_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    PODOFO_BASE_DIR="$8"
fi

if [ -z "$9" ]; then
  echo "Please provide the path to your zlib folder (e.g., ../zlib)"
  read -r ZLIB_BASE_DIR

  # Exit if no input is provided after prompt
  if [ -z "$ZLIB_BASE_DIR" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    ZLIB_BASE_DIR="$9"
fi

if [ -z "$10" ]; then
  echo "Please provide the path to your target folder (e.g., ../install)"
  read -r TARGET_PATH

  # Exit if no input is provided after prompt
  if [ -z "$TARGET_PATH" ]; then
    echo "No input provided. Exiting."
    exit 1
  fi
else
    TARGET_PATH="${10}"
fi

# Iterate over android archs
ARCHS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

for ARCH in "${ARCHS[@]}"; do
    # Create directories if they don't exist
    mkdir -p "$TARGET_PATH/install/$ARCH/lib"

    # Copy PoDoFo libraries
    cp "$PODOFO_BASE_DIR/$ARCH/lib/libpodofo.a" "$TARGET_PATH/install/$ARCH/lib/"
    cp "$PODOFO_BASE_DIR/$ARCH/lib/libpodofo_private.a" "$TARGET_PATH/install/$ARCH/lib/"
    cp "$PODOFO_BASE_DIR/$ARCH/lib/libpodofo_3rdparty.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy Brotli libraries (just copy them individually)
    cp "$BROTLI_BASE_DIR/$ARCH/lib/libbrotlicommon-static.a" "$TARGET_PATH/install/$ARCH/lib/libbrotli.a"
    cp "$BROTLI_BASE_DIR/$ARCH/lib/libbrotlidec-static.a" "$TARGET_PATH/install/$ARCH/lib/libbrotlidec.a"
    cp "$BROTLI_BASE_DIR/$ARCH/lib/libbrotlienc-static.a" "$TARGET_PATH/install/$ARCH/lib/libbrotlienc.a"

    # Copy bzip2 library
    cp "$BZIP2_BASE_DIR/$ARCH/lib/libbz2.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy FreeType library
    cp "$FREETYPE_BASE_DIR/$ARCH/lib/libfreetype.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy HarfBuzz library
    cp "$HARFBUZZ_BASE_DIR/$ARCH/lib/libharfbuzz.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy libpng library
    cp "$LIBPNG_BASE_DIR/$ARCH/lib/libpng.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy libxml2 library
    cp "$LIBXML2_BASE_DIR/$ARCH/lib/libxml2.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy OpenSSL libraries
    cp "$OPENSSL_BASE_DIR/$ARCH/lib/libssl.a" "$TARGET_PATH/install/$ARCH/lib/"
    cp "$OPENSSL_BASE_DIR/$ARCH/lib/libcrypto.a" "$TARGET_PATH/install/$ARCH/lib/"

    # Copy zlib library
    cp "$ZLIB_BASE_DIR/$ARCH/lib/libz.a" "$TARGET_PATH/install/$ARCH/lib/"

    mkdir -p $TARGET_PATH/install/$ARCH/include

    # Copy headers
    cp -r "$PODOFO_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$BROTLI_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$BZIP2_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$FREETYPE_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$HARFBUZZ_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$LIBPNG_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$LIBXML2_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$OPENSSL_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
    cp -r "$ZLIB_BASE_DIR/$ARCH/include/"* "$TARGET_PATH/install/$ARCH/include/"
done

echo "Libraries copied and organized successfully!"
