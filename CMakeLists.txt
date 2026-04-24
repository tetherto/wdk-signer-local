cmake_minimum_required(VERSION 4.0)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)

project(bare_signer C)

add_bare_module(bare_signer)

target_sources(
  ${bare_signer}
  PRIVATE
    binding.c
    binding_android.c
    binding_darwin.c
    shared.c
)

# MSVC flags POSIX names like `strdup` as deprecated in favor of
# underscore-prefixed variants. Opt out of the nag so shared code compiles
# cleanly across toolchains.
if (MSVC)
  target_compile_definitions(${bare_signer} PRIVATE _CRT_NONSTDC_NO_DEPRECATE)
endif()
