
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginexfil_detect)

include(ZeekPlugin)

zeek_plugin_begin(Exfiltration exfil_detect ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_bif(src/exfil_detect.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(
        scripts/__load__.zeek
        scripts/__preload__.zeek
        scripts/types.zeek
        scripts/Exfiltration/exfil_detect/__load__.zeek
)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
