cmake_minimum_required(VERSION 2.8.10)

set(PROJECT_NAME udapd)
project(${PROJECT_NAME})

macro(add_cflags)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARGN}")
endmacro(add_cflags)

macro(add_cxxflags)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARGN}")
endmacro(add_cxxflags)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
  add_cxxflags("-std=c++11")
else()
  message(ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

if(STATIC_LINK)
  set(STATIC_LINK_LIBS c)
  add_cflags("-static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
  add_cxxflags("-static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
endif()

if(SHADOW)
  set(WITH_STATIC OFF)
else()
  set(WITH_STATIC ON)
endif()

set(DEBUG_FLAGS "-g")
set(OPTIMIZE_FLAGS "-O0")

if(ASAN)
  set(DEBUG_FLAGS "${DEBUG_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(OPTIMIZE_FLAGS "-O0")
endif(ASAN)

if(SHADOW)
  if("${SHADOW_ROOT}" STREQUAL "")
    set(SHADOW_ROOT "$ENV{HOME}/.shadow")
  endif("${SHADOW_ROOT}" STREQUAL "")
  if(EXISTS "${SHADOW_ROOT}")
    message(STATUS "SHADOW_ROOT = ${SHADOW_ROOT}")
  else()
    message(FATAL_ERROR "SHADOW_ROOT path does not exist: '${SHADOW_ROOT}'")
  endif()
  set(CMAKE_MODULE_PATH "${SHADOW_ROOT}/share/cmake/Modules")
  include_directories(${CMAKE_MODULE_PATH})
  include(ShadowTools)
  add_cxxflags("-fno-inline -fno-strict-aliasing")
  add_cflags("-fno-inline -fno-strict-aliasing")

  add_definitions(-DTESTNET=true)
  add_definitions(-DSHADOW_TESTNET)
  include_directories(${SHADOW_ROOT}/include)
endif()

add_cflags("-Wall -Wno-deprecated-declarations ${OPTIMIZE_FLAGS}")
add_cxxflags("-Wall -Wno-deprecated-declarations ${OPTIMIZE_FLAGS}")

if(CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
  add_cflags("${DEBUG_FLAGS}")
  add_cxxflags("${DEBUG_FLAGS}")
endif()

if(SHADOW)
  add_cflags("-fPIC")
  add_cxxflags("-fPIC")
endif()

if(NOT GIT_VERSION)
  exec_program("git" ${CMAKE_CURRENT_SOURCE_DIR} ARGS "rev-parse --short HEAD" OUTPUT_VARIABLE GIT_VERSION)
  add_definitions(-DGIT_REV="${GIT_VERSION}")
endif()

if(RELEASE_MOTTO)
  add_definitions(-DUDAP_RELEASE_MOTTO="${RELEASE_MOTTO}")
endif()

set(EXE udapd)
set(EXE_SRC daemon/main.c)

if(SODIUM_INCLUDE_DIR)
  include_directories(${SODIUM_INCLUDE_DIR})
endif()

if(SODIUM_LIBRARIES)
  set(SODIUM_LIB ${SODIUM_LIBRARIES})
else()
  set(SODIUM_LIB sodium)
endif()

set(LIBS ${SODIUM_LIB} pthread)

set(LIB udap)
set(SHARED_LIB ${LIB})
set(STATIC_LIB ${LIB}-static)

set(LIB_SRC
  udap/address_info.cpp
  udap/bencode.c
  udap/buffer.cpp
  udap/config.cpp
  udap/context.cpp
  udap/crypto_async.cpp
  udap/crypto_libsodium.cpp
  udap/dht.cpp
  udap/encode.cpp
  udap/encrypted_frame.cpp
  udap/ev.cpp
  udap/exit_info.cpp
  udap/exit_route.c
  udap/iwp_link.cpp
  udap/logger.cpp
  udap/link.c
  udap/link_intro.cpp
  udap/link_message.cpp
  udap/logic.cpp
  udap/mem.cpp
  udap/net.cpp
  udap/nodedb.cpp
  udap/path.cpp
  udap/pathbuilder.cpp
  udap/pathset.cpp
  udap/proofofwork.cpp
  udap/relay_ack.cpp
  udap/relay_commit.cpp
  udap/relay_up_down.cpp
  udap/router_contact.cpp
  udap/router.cpp
  udap/threadpool.cpp
  udap/transit_hop.cpp
  udap/testnet.c
  udap/time.cpp
  udap/timer.cpp
  udap/api/create_session.cpp
  udap/api/client.cpp
  udap/api/message.cpp
  udap/api/parser.cpp
  udap/routing/message_parser.cpp
  udap/routing/path_confirm.cpp
  udap/routing/path_latency.cpp
  vendor/cppbackport-master/lib/fs/rename.cpp
  vendor/cppbackport-master/lib/fs/filestatus.cpp
  vendor/cppbackport-master/lib/fs/filetype.cpp
  vendor/cppbackport-master/lib/fs/cleanpath.cpp
  vendor/cppbackport-master/lib/fs/perms.cpp
  vendor/cppbackport-master/lib/fs/equivalent.cpp
  vendor/cppbackport-master/lib/fs/current_path.cpp
  vendor/cppbackport-master/lib/fs/basename.cpp
  vendor/cppbackport-master/lib/fs/tempdir.cpp
  vendor/cppbackport-master/lib/fs/create_directory.cpp
  vendor/cppbackport-master/lib/fs/path.cpp
  vendor/cppbackport-master/lib/fs/remove.cpp
  vendor/cppbackport-master/lib/fs/diriter.cpp
  vendor/cppbackport-master/lib/fs/copyfile.cpp
  vendor/cppbackport-master/lib/fs/absolute.cpp
  vendor/cppbackport-master/lib/fs/direntry.cpp
)

set(TEST_SRC 
  test/main.cpp
  test/api_unittest.cpp
  test/dht_unittest.cpp
  test/encrypted_frame_unittest.cpp
)
set(TEST_EXE testAll)
set(GTEST_DIR test/gtest)

set(CLIENT_EXE udapc)

set(CLIENT_SRC 
  client/main.cpp
)

# TODO: exclude this from includes and expose stuff properly for rcutil
include_directories(udap)

include_directories(include)
include_directories(vendor/cppbackport-master/lib)



if(SHADOW)
  add_shadow_plugin(shadow-plugin-${SHARED_LIB} ${EXE_SRC} ${LIB_SRC})
  target_link_libraries(shadow-plugin-${SHARED_LIB} ${LIBS})
  install(TARGETS shadow-plugin-${SHARED_LIB} DESTINATION plugins)
else()
  
  add_executable(rcutil daemon/rcutil.cpp)
  add_executable(${EXE} ${EXE_SRC})
  add_executable(${CLIENT_EXE} ${CLIENT_SRC}) 

  if(WITH_TESTS)
    enable_testing()
    add_subdirectory(${GTEST_DIR})
    include_directories(${GTEST_DIR}/include ${GTEST_DIR})
    add_executable(${TEST_EXE} ${TEST_SRC})
    add_test(runAllTests ${TEST_EXE})
    target_link_libraries(${TEST_EXE} ${STATIC_LINK_LIBS} gtest_main ${STATIC_LIB})
  endif()

  if(WITH_STATIC)
    add_library(${STATIC_LIB} STATIC ${LIB_SRC})
    target_link_libraries(${STATIC_LIB} ${LIBS})
    if(NOT WITH_SHARED)
      target_link_libraries(rcutil ${STATIC_LINK_LIBS} ${STATIC_LIB})
      target_link_libraries(${EXE} ${STATIC_LINK_LIBS} ${STATIC_LIB})
      target_link_libraries(${CLIENT_EXE} ${STATIC_LINK_LIBS} ${STATIC_LIB})
    endif()
  endif()
  
  if(WITH_SHARED)
    add_library(${SHARED_LIB} SHARED ${LIB_SRC})
    target_link_libraries(${SHARED_LIB} ${LIBS})
    if(NOT WITH_STATIC)
      target_link_libraries(rcutil ${SHARED_LIB})
      target_link_libraries(${EXE} ${SHARED_LIB})
    endif()
  endif()

endif()
