cmake_minimum_required(VERSION 3.16)
set(SODIR "so")
set(LIBDIR "lib")
set(INCLUDEDIR "include")
set(BINDIR "bin")
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_LIST_DIR}/out)

project(Network
    VERSION 1.0.1
    DESCRIPTION "Network Library for Distributed System"
)

add_library(ttnetwork_so SHARED src/Network.cpp)
add_library(ttnetwork_so_dbg SHARED src/Network.cpp)
add_library(ttnetwork_a STATIC src/Network.cpp)
add_library(ttnetwork_a_dbg STATIC src/Network.cpp)

set_property(TARGET ttnetwork_so PROPERTY CXX_STANDARD_REQUIRED 11)
set_property(TARGET ttnetwork_so PROPERTY CXX_STANDARD 11)
set_property(TARGET ttnetwork_so_dbg PROPERTY CXX_STANDARD_REQUIRED 11)
set_property(TARGET ttnetwork_so_dbg PROPERTY CXX_STANDARD 11)
set_property(TARGET ttnetwork_a PROPERTY CXX_STANDARD_REQUIRED 11)
set_property(TARGET ttnetwork_a PROPERTY CXX_STANDARD 11)
set_property(TARGET ttnetwork_a_dbg PROPERTY CXX_STANDARD_REQUIRED 11)
set_property(TARGET ttnetwork_a_dbg PROPERTY CXX_STANDARD 11)

set_target_properties(ttnetwork_so PROPERTIES 
    OUTPUT_NAME ttnetwork
    VERSION ${PROJECT_VERSION}
	PUBLIC_HEADER "src/Network.h;src/SocketException.h"
)
set_target_properties(ttnetwork_so_dbg PROPERTIES 
    OUTPUT_NAME ttnetwork_dbg
	VERSION ${PROJECT_VERSION}
	PUBLIC_HEADER "src/Network.h;src/SocketException.h"
)
set_target_properties(ttnetwork_a PROPERTIES 
    OUTPUT_NAME ttnetwork
    VERSION ${PROJECT_VERSION}
	PUBLIC_HEADER "src/Network.h;src/SocketException.h"
)
set_target_properties(ttnetwork_a_dbg PROPERTIES 
    OUTPUT_NAME ttnetwork_dbg
	VERSION ${PROJECT_VERSION}
	PUBLIC_HEADER "src/Network.h;src/SocketException.h"
)

target_compile_definitions(ttnetwork_so PUBLIC TTDEBUG=0)
target_compile_definitions(ttnetwork_so_dbg PUBLIC TTDEBUG=1)
target_compile_definitions(ttnetwork_a PUBLIC TTDEBUG=0)
target_compile_definitions(ttnetwork_a_dbg PUBLIC TTDEBUG=1)

install(
TARGETS ttnetwork_so ttnetwork_a ttnetwork_so_dbg ttnetwork_a_dbg
RUNTIME DESTINATION ${BINDIR}
LIBRARY DESTINATION ${SODIR}
ARCHIVE DESTINATION ${LIBDIR}
PUBLIC_HEADER DESTINATION ${INCLUDEDIR}
)
