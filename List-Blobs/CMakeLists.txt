cmake_minimum_required(VERSION 2.8)

project(ListBlobs)

set(COMMON_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/../common/src)
set(COMMON_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../common/inc)

include_directories(${COMMON_INCLUDE})

message(STATUS $ENV{SYS_ROOT})
message(STATUS $ENV{HOME})

add_executable(listblobs 
	main.cpp 
	${COMMON_SOURCE}/AzureStorageAuthenticationHelper.cpp 
	${COMMON_SOURCE}/sha256.c)
	
target_link_libraries(listblobs curl ssl crypto)