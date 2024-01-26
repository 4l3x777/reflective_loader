cmake_minimum_required(VERSION 3.22)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(REFLECTIVE_LOADER VERSION ${PROJECT_VESRION})

include_directories(include src tests/hello_msb)

add_executable(
  hello_msb
  tests/hello_msb/hello_msb.cpp
)

add_executable(
  reflective_loader
  src/reflective_loader.cpp 
  src/main.cpp
)

set_target_properties(
  reflective_loader
  hello_msb
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
)

if (MSVC)
  target_compile_options(reflective_loader PRIVATE /W4)

  target_compile_options(hello_msb PRIVATE /W4)
else ()
  target_link_options(reflective_loader PRIVATE -static-libgcc -static-libstdc++)

  target_link_options(hello_msb PRIVATE -static-libgcc -static-libstdc++)

  target_compile_options(
    reflective_loader 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )

  target_compile_options(
    hello_msb 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )
endif()

install(
    TARGETS 
    reflective_loader hello_msb
    RUNTIME DESTINATION . COMPONENT release
)

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL release)

# CPack area
if (WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")
set(CPACK_PACKAGE_CONTACT https://github.com/4l3x777/reflective_loader)
include(CPack)