# RTProtect — Quickstart Guide

This guide describes how to install, integrate, and deploy RTProtect on Windows x64.

---

## 1. Package Overview

RTProtect releases provide three distinct artifacts:

1. **`rtprotect-windows-x64.zip`**: Tools and runtime executables.
   - `bin/rtprotect-tool.exe` — Command-line integration engine and AST scanner.
   - `bin/rtprotect-gui.exe` — Graphical protection profiler and project inspector.
   - `bin/rtprotect-bench.exe` — Protection benchmark and overhead measurement runner.
   - Runtime dependencies (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`).

2. **`rtprotect-sdk-windows-x64.zip`**: Developer SDK for C++ applications.
   - `include/` — C++20 header files (`bytecode_vm`, `integrity`, `crypto`, `licensing`, `antitamper`, `obfuscation`).
   - `lib/` — Precompiled static libraries.
   - `cmake/` — CMake package configuration (`RTProtectConfig.cmake`, `RTProtectTargets.cmake`).
   - `examples/consumer_sample/` — Complete consumer application demonstrating CMake integration.

3. **`rtprotect-activation-server-windows-x64.zip`**: Licensing authority server.
   - `bin/rtprotect-activation-server.exe` — High-performance HTTP/TLS server for activation tokens.
   - Runtime dependencies (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`).

---

## 2. Using the CLI and GUI Tools

### Automatic Protection Integration
To protect an existing C++ project (CMake or Unreal Engine):

```cmd
# Inspect and protect with Balanced profile
bin\rtprotect-tool.exe --source C:\Projects\MyGame --profile balanced

# Or launch the graphical user interface
bin\rtprotect-gui.exe
```

---

## 3. Integrating the SDK into a C++ Project

### CMake Integration (`CMakeLists.txt`)
Set `CMAKE_PREFIX_PATH` to the extracted SDK directory:

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyProtectedApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Discover RTProtect SDK
find_package(RTProtect CONFIG REQUIRED)

add_executable(MyProtectedApp main.cpp)

# Link desired protection modules
target_link_libraries(MyProtectedApp PRIVATE
    RTProtect::rtprotect_licensing
    RTProtect::rtprotect_antitamper
    RTProtect::rtprotect_vm
    RTProtect::rtprotect_integrity
    RTProtect::rtprotect_crypto
)
```

### Application Code Example (`main.cpp`)
```cpp
#include <iostream>
#include <antitamper/anti_debug.h>
#include <licensing/hardware_id.h>

int main() {
    // 1. Anti-debugging and environment integrity verification
    if (rtprotect::antitamper::CheckDebuggerPresent()) {
        std::cerr << "Debugger detected. Terminating.\n";
        return 1;
    }

    // 2. Hardware ID derivation
    std::string hwid = rtprotect::licensing::GetLocalHardwareId();
    std::cout << "Machine Hardware Fingerprint: " << hwid << "\n";
    std::cout << "Protection initialized successfully.\n";
    return 0;
}
```

---

## 4. Running the Activation Server

### Starting the Server
```cmd
# Run server on port 8080 (loopback interface)
bin\rtprotect-activation-server.exe --port 8080 --host 127.0.0.1 --db activations.db
```

### Registering a Customer License
```cmd
bin\rtprotect-activation-server.exe --db activations.db --register-license "LIC-PROD-100" "my-product" 5
```

### Production Deployment
For external network interfaces, specify TLS certificates:
```cmd
bin\rtprotect-activation-server.exe --port 8443 --host 0.0.0.0 --tls-cert cert.pem --tls-key key.pem --admin-token-file admin_token.txt
```
