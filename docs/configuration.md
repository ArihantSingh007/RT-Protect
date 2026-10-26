# Configuration and Policy Reference

## 1. Configuration Layers

RTProtect operates across four distinct configuration layers:
1. **Compile-Time CMake Options:** Control feature enablement and build targets.
2. **Protection Profiles:** Control compiler flags, linker flags, and anti-tamper risk thresholds.
3. **Runtime Environment Variables:** Configure credentials, paths, and build overrides.
4. **Activation Server Options:** Control service ports, database encryption keys, and DPAPI vaults.

---

## 2. Hardening Profiles

When protecting a project via `rtprotect-tool integrate --profile <name>`, the integration engine configures compiler flags, linker flags, and runtime risk policies:

| Security Attribute | `dev` Profile | `balanced` Profile (Default) | `maximum` Profile |
|:---|:---:|:---:|:---:|
| **Target Audience** | Local development and debugging | Production commercial games & software | High-value enterprise & anti-cheat binaries |
| **Compiler Optimization** | `-O0` / `/Od` | `-O2` / `/O2` | `-O3` / `/Ox /GL /Gw` |
| **Control Flow Guard (CFG)** | Disabled | Enabled (`/guard:cf`) | Enabled (`/guard:cf,ehcont`) |
| **Stack Protection** | Standard | Enabled (`/GS`) | Maximum (`/GS` / `-fstack-protector-strong`) |
| **Link-Time Code Gen (LTCG)** | Disabled | Enabled (`/LTCG`) | Enabled (`/LTCG /OPT:REF /OPT:ICF`) |
| **Strip Memory Headers** | Disabled | Enabled | Enabled |
| **Hardware Breakpoint Watchdog** | Disabled | Enabled | Enabled |
| **Anti-Dump Memory Protection** | Disabled | Enabled | Enabled |
| **Environment Risk Action** | `kReportOnly` (Logs only) | `kRestrict` (Rejects if score >= 50) | `kTerminate` (Exits if score >= 80) |
| **Development Key Fallback** | Allowed | Disallowed in production | Disallowed |

---

## 3. CMake Configuration Options

These options are specified when invoking `cmake` to configure the RTProtect build:

| CMake Option | Default | Description |
|:---|:---:|:---|
| `RTPROTECT_BUILD_TESTS` | `OFF` | Enables compilation of all 26 automated unit and end-to-end test suites. |
| `RTPROTECT_BUILD_FUZZERS` | `OFF` | Enables compilation of LLVM libFuzzer targets (requires Clang). |
| `RTPROTECT_ENABLE_EXPERIMENTAL_RUNTIME_RECONSTRUCTION` | `OFF` | Enables the experimental Phase 6 runtime native reconstruction engine. |
| `OPENSSL_ROOT_DIR` | `""` | Absolute path to the OpenSSL installation containing `include/`, `lib/`, and `bin/`. |
| `CMAKE_BUILD_TYPE` | `Release` | Build configuration (`Debug`, `Release`, `RelWithDebInfo`, `MinSizeRel`). |

---

## 4. Source Annotations & Macros

### 4.1 `@rtprotect_virtualize`
Placed directly above C++ functions to mark them for AST-based virtualization:
```cpp
// @rtprotect_virtualize
std::int64_t ComputeEntitlement(std::int64_t base, std::int64_t multiplier) {
    return base * multiplier + 7;
}
```

### 4.2 `RTPROTECT_ENABLED`
Defined as `1` in `rtprotect_config.h` when protection has been applied by `rtprotect-tool integrate`. Enables conditional compilation for protected vs. development builds.

### 4.3 `kBuildOpcodeSeed`
A unique 32-bit integer embedded into `rtprotect_config.h` per integration run. Initializes the randomized opcode table used by `rtprotect::vm::OpcodeMap`.

---

## 5. Runtime Environment Variables

| Variable | Scope | Description |
|:---|:---|:---|
| `RTPROTECT_ACTIVATION_CREDENTIAL` | Client Application | Secret activation credential string used to authorize online license activation when authenticating against an activation server. |
| `CMAKE_GENERATOR` | Integration Engine | Overrides the CMake generator used during `rtprotect-tool integrate` validation builds (e.g. `Visual Studio 17 2022` or `Ninja`). |
| `CMAKE_BUILD_TYPE` | Integration Engine | Overrides the build configuration used during integration builds (e.g. `Release` or `Debug`). |
| `PATH` | System Runtime | Must contain the directory of `libcrypto-*.dll` and `libssl-*.dll` if OpenSSL DLLs are not colocated with the executable. |

---

## 6. Activation Server Configuration

The `rtprotect-activation-server` executable accepts options via command-line arguments:

| Option | Argument | Default | Description |
|:---|:---:|:---:|:---|
| `--port` | `<1-65535>` | `8080` | TCP port on which the HTTP/HTTPS server listens. |
| `--host` | `<address>` | `127.0.0.1` | Network interface IP to bind to (`0.0.0.0` for all interfaces). |
| `--db` | `<path>` | `activations.db` | File path for the activation database. |
| `--db-key` | `<hex|file>` | `""` | 64-character hex key or 32-byte binary file for database envelope encryption. |
| `--db-vault-id` | `<id>` | `""` | Vault key ID used to retrieve the database encryption key from DPAPI. |
| `--provision-db-vault` | `<id>` | `""` | Generates a new 256-bit AES database key directly into the DPAPI vault and exits. |
| `--tls-cert` | `<path>` | `""` | Path to TLS certificate in PEM format. |
| `--tls-key` | `<path>` | `""` | Path to TLS private key in PEM format. |
| `--vault-id` | `<id>` | `""` | Vault key ID used to retrieve the Ed25519 token signing private key from DPAPI. |
| `--provision-vault` | `<id> <pub>` | `""` | Generates a new Ed25519 key into the vault, exports public key to `<pub>`, and exits. |
| `--admin-token` | `<token>` | `""` | Shared secret token required to access administrative `/events` and `/analytics` endpoints. |
| `--admin-token-file` | `<path>` | `""` | Path to file containing the administrative shared secret token. |
| `--insecure-dev-only` | None | `false` | Development escape hatch: permits unencrypted plaintext keys and HTTP connections. |
| `--allow-legacy-db-plaintext` | None | `false` | Permits loading unencrypted legacy VM roots from existing databases. |
| `--migrate-db` | None | `false` | Re-encrypts all database VM roots under the configured envelope key and exits. |

---

## 7. License Capability Bitmasks

Licenses enforce capability flags represented as a 64-bit integer bitmask:

| Bit Position | Value (Hex) | Capability Name | Description |
|:---:|:---:|:---|:---|
| 0 | `0x0000000000000001` | `core` | Authorizes standard binary execution and VM dispatch. |
| 1 | `0x0000000000000002` | `commercial` | Authorizes commercial usage without watermark banners. |
| 2 | `0x0000000000000004` | `enterprise` | Authorizes enterprise features, cluster deployments, and elevated seat limits. |
| 3 | `0x0000000000000008` | `offline_grace` | Authorizes offline execution during network connectivity interruptions. |
| 4 | `0x0000000000000010` | `eval` | Designates an evaluation license with strict time-limited expiration. |
