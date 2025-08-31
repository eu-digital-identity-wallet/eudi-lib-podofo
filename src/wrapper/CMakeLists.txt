cmake_minimum_required(VERSION 3.4.1)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the PoDoFo library
find_library(PODOFO_LIBRARY podofo)

# Add the source files
add_library(podofo SHARED
            podofo_jni.cpp
            podofo_jni.h)

# Include directories
target_include_directories(podofo PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/podofo
    ${CMAKE_SOURCE_DIR}/include/podofo/main
    ${CMAKE_SOURCE_DIR}/include/podofo/auxiliary
    ${CMAKE_SOURCE_DIR}/include/podofo/optional
    ${CMAKE_SOURCE_DIR}/include/podofo/3rdparty
)

# Set 16KB alignment for Android compatibility
if(ANDROID)
    set_target_properties(podofo PROPERTIES
        LINK_FLAGS "-Wl,-z,max-page-size=16384"
    )
endif()

# Link against required libraries
target_link_libraries(podofo
    ${PODOFO_LIBRARY}
)