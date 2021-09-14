find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

add_library(src
        common/functionalities.cpp
        common/helpers.cpp
        common/table_opprf.cpp
        ots/ots.cpp
        )

set_target_properties(src
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(src
        PRIVATE
        -march=native
        -ffunction-sections -mpclmul -mbmi2 -maes
        -mavx -msse2 -msse3 -msse4.1 -mrdrnd
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

target_link_libraries(src INTERFACE
        ABY::aby
        ENCRYPTO_utils::encrypto_utils
        ${GLIB_LDFLAGS}
        gmp
        gmpxx
        ntl
        HashingTables
        libOTe
        Boost::program_options
        Threads::Threads
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        )

target_include_directories(src PUBLIC
        ${PSI_ANALYTICS_SOURCE_ROOT}/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/HashingTables
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/EzPC/SCI/src
        ${GLIB_INCLUDE_DIRS}
        )

if (PSI_ANALYTICS_BUILD_EXAMPLE)
    add_executable(gcf_psi circuit_psi.cpp)

    target_link_libraries(gcf_psi PUBLIC
            src
            )
    set_target_properties(gcf_psi
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif (PSI_ANALYTICS_BUILD_EXAMPLE)
