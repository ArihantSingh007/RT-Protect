cmake_minimum_required(VERSION 3.20)
project(SampleClientApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sample_client_app
    main.cpp
)
