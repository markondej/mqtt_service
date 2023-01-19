cmake_minimum_required(VERSION 3.10)
project(mqtt_service DESCRIPTION "Light MQTT Service" VERSION 0.9.2)

set(EXECUTABLE mqtt_service)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

cmake_policy(SET CMP0076 NEW)

add_executable(${EXECUTABLE} mqtt/service.hpp mqtt/service.cpp mqtt_service.cpp)

if (WIN32)
	target_sources(${EXECUTABLE}
		PRIVATE about_window.cpp
		PUBLIC about_window.hpp
		PRIVATE console_window.cpp
		PUBLIC console_window.hpp
		PRIVATE windows/product_info.cpp
		PUBLIC windows/product_info.hpp
		PRIVATE windows/window.cpp
		PUBLIC windows/window.hpp
		PRIVATE resources/manifest.xml
		PRIVATE resources/resource.rc
		PUBLIC resources/resource.h
	)

if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS /MANIFEST:NO")
	target_link_libraries(${EXECUTABLE} version.lib)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()
else()
	target_sources(${EXECUTABLE}
		PUBLIC console.hpp
	)

	target_link_libraries(${EXECUTABLE} pthread atomic)
	add_definitions(-DPRODUCT_NAME="${CMAKE_PROJECT_DESCRIPTION}" -DPRODUCT_VERSION="${CMAKE_PROJECT_VERSION})"
endif()