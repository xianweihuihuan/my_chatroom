cmake_minimum_required(VERSION 3.1.3)
project(chatroom)

set(CMAKE_BUILD_TYPE DEBUG)


set(target "chat_server")

set(proto_srcs "")
set(proto_path ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
set(proto_files chat.proto)
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


set(odb_path ${CMAKE_CURRENT_SOURCE_DIR}/../odb)
set(odb_files chat_session_member.hxx chat_session.hxx friend_apply.hxx message.hxx relation.hxx user.hxx)
set(odb_srcs "")
foreach(odb_file ${odb_files})
  string(REPLACE ".hxx" "-odb.hxx" odb_hxx ${odb_file})
  string(REPLACE ".hxx" "-odb.cxx" odb_cxx ${odb_file})
  if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${odb_cxx})
    add_custom_command(
      PRE_BUILD
      COMMAND odb
      ARGS -d mysql --std c++11 --generate-query --generate-schema --profile boost/date-time ${odb_path}/${odb_file}
      DEPENDS ${odb_path}/${odb_file}
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${odb_cxx}
      COMMENT "生成ODB框架代码文件：" ${CMAKE_CURRENT_BINARY_DIR}/${odb_cxx}
    )
  endif()
  list(APPEND odb_srcs ${CMAKE_CURRENT_BINARY_DIR}/${odb_cxx})
endforeach()


set(src_file,"")
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/../common src_file)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/../muduo src_file)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/source src_file)
add_executable(${target} ${src_file} ${odb_srcs} ${proto_srcs})

target_link_libraries(${target} -lgflags -lspdlog -lfmt -lssl -lcrypto -lprotobuf -lcpprest -lcurl -lcpr -lhiredis -lredis++ -lodb -lodb-mysql -lodb-boost /usr/lib/x86_64-linux-gnu/libjsoncpp.so.19)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../odb)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../muduo)

