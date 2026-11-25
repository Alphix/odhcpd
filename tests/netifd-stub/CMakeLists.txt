cmake_minimum_required(VERSION 3.13)

# netifd-stub: minimal netifd stand-in for the odhcpd network lab (LAB.md),
# built by tests/lab build
project(netifd-stub LANGUAGES C)
add_executable(${PROJECT_NAME} netifd-stub.c)
target_compile_definitions(${PROJECT_NAME} PRIVATE _GNU_SOURCE)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter -Os -g)

find_path(ubox_include_dir libubox/uloop.h)
find_path(ubus_include_dir libubus.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${ubox_include_dir} ${ubus_include_dir})
find_library(libubox ubox)
find_library(libblobmsg_json blobmsg_json)
find_library(libubus ubus)
target_link_libraries(${PROJECT_NAME} PRIVATE ${libubus} ${libblobmsg_json} ${libubox})

install(TARGETS ${PROJECT_NAME} DESTINATION sbin/)
