set(LIB_NAME lz4)

set(TARGET_NAME ${LIB_NAME})
add_library(${TARGET_NAME})

add_library(${PROJECT_NAME}::${LIB_NAME} ALIAS ${TARGET_NAME})

set(LZ4_SOURCES
    src/lz4.c
    src/lz4file.c
    src/lz4frame.c
    src/lz4hc.c
    src/xxhash.c
)

target_sources(${TARGET_NAME} PRIVATE ${LZ4_SOURCES})
target_include_directories(${TARGET_NAME} PUBLIC inc)

set_target_properties(${TARGET_NAME} PROPERTIES rb_export_as_package_component ${PROJECT_NAME}::${LIB_NAME})
