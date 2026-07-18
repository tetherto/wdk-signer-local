cmake_minimum_required(VERSION 3.22.1)

project("android-lib")

# Create the JNI shared library
add_library(android-lib SHARED
    native-lib.cpp
)

# Find required libraries
find_library(log-lib log)

# Link libraries
target_link_libraries(android-lib
    ${log-lib}
)

# Set C++ standard
set_target_properties(android-lib PROPERTIES
        OUTPUT_NAME "bare-signer-android"
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
)