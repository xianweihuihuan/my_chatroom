cmake_minimum_required(VERSION 3.1.3)
project(chatroom)

set(target "client")



set(proto_srcs "")
set(proto_path ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
set(proto_files chat.proto file.proto)
foreach(proto_file ${proto_files})
  string(REPLACE ".proto" ".pb.cc" proto_cc ${proto_file})
  string(REPLACE ".proto" ".pb.h" proto_h ${proto_file})
  if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${proto_cc})
    add_custom_command(
      PRE_BUILD
      COMMAND protoc
      ARGS --cpp_out=${CMAKE_CURRENT_BINARY_DIR} -I${proto_path} --experimental_allow_proto3_optional ${proto_path}/${proto_file}
      DEPENDS ${proto_path}/${proto_file}
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${proto_cc}
      COMMENT "生成Protobuf框架代码文件:" ${CMAKE_CURRENT_BINARY_DIR}/${proto_cc}
    )
  endif()
  list(APPEND proto_srcs ${CMAKE_CURRENT_BINARY_DIR}/${proto_cc})
endforeach()

set(src_files "")
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/source src_files)
list(APPEND src_files ${CMAKE_CURRENT_SOURCE_DIR}/../muduo/Socket.cc)
list(APPEND src_files ${CMAKE_CURRENT_SOURCE_DIR}/../muduo/Buffer.cc)
list(APPEND src_files ${CMAKE_CURRENT_SOURCE_DIR}/../common/logger.cc)

add_executable(${target} ${src_files} ${proto_srcs})
target_link_libraries(${target}  -lgflags -lspdlog -lfmt  -lssl -lcrypto -lprotobuf -lleveldb  -lcpprest -lcurl)


include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../muduo)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common)

