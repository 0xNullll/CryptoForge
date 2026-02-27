# Build and Install

This document describes building and installing **CryptoForge** on supported operating systems: Linux and Windows.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Notational Conventions](#notational-conventions)
- [Quick Build Guide](#quick-build-guide)
- [Build Types](#build-types)
- [Library Options](#library-options) 
- [Test Executable](#test-executable)
- [Optional Flags](#optional-flags)
- [Output Directory](#output-directory)
- [Build Commands](#build-commands)
- [Recommended Workflow](#recommended-workflow)
- [Notes](#notes)

---

## Prerequisites

**Keep in mind:** The default output directory is not a privileged or secure location. CryptoForge is currently experimental and educational. It does not place libraries in system-protected directories, so exercise caution with access permissions.

To build CryptoForge, you will need:

- A C compiler supporting **C11**
- CMake version **3.24 or higher**
- Make or Ninja on Linux, or Visual Studio / MSBuild on Windows
- Development headers and libraries for your OS

---

## Notational Conventions

### Commands
Lines starting with `$` represent a shell prompt or command line input. **Do not type the `$` itself**; it is just an indicator for the prompt.

**Example:**
```bash
$ <command here>
```

### Optional Arguments
Arguments in square brackets `[OPTION]` are optional. You may include them or leave them out.

**Example:**
```bash
$ cmake -S . -B build [options]
```

### Choices
Curly braces with pipes `{CHOICE1|CHOICE2}` indicate a mandatory selection. You must pick **one** of the options.

**Example:**
```bash
$ cmake --build build --config {Debug|Release|RelWithDebInfo|MaxOptRelease}
```

### Combined Notation
You can combine optional arguments and choices for more complex commands:
```bash
$ <command> [--flag1] [--flag2] {option1|option2}
```

### All-in-One Example Command
```bash
$ cmake -S . -B build_{Debug|Release|RelWithDebInfo|MaxOptRelease} \
    -DCMAKE_BUILD_TYPE={Debug|Release|RelWithDebInfo|MaxOptRelease} \
    -DCF_LINK_SHARED={ON|OFF} \
    -DCF_BUILD_TESTS={ON|OFF} \
    -DENABLE_CF_TESTS_VERBOSE={ON|OFF} \
    -DENABLE_CF_BARRIER={ON|OFF} \
    -DENABLE_CF_BASE_TRUNC={ON|OFF} \
    -DENABLE_CF_DEBUG={ON|OFF} \
    [-DOUTPUT_DIR=<directory>]
```
This demonstrates mandatory choices `{}` and optional arguments `[]`.

---

## Quick Build Guide

To build a Release version with shared library and verbose tests:

### Linux / Windows
```bash
$ cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DCF_LINK_SHARED=ON -DENABLE_CF_TESTS_VERBOSE=ON
$ cmake --build build_release --config Release
$ ctest --test-dir build_release --output-on-failure -C Release
```
This produces the library and test executable in the build folder.

---

## Build Types

| Build Type       | Purpose                                   |
|------------------|-------------------------------------------|
| Debug            | Development with debug info               |
| RelWithDebInfo   | Optimized with debug info                 |
| Release          | Standard optimized build                  |
| MaxOptRelease    | Maximum optimization for performance      |

---

## Library Options

| Option                        | Default | Description |
|-------------------------------|---------|-------------|
| CF_LINK_SHARED                | OFF     | Build shared (.dll/.so) or static (.lib/.a) library |
| CF_BUILD_TESTS                | ON      | Build test executable (`cf_tests`) |
| ENABLE_CF_TESTS_VERBOSE       | OFF     | Enable verbose test output |
| ENABLE_CF_BARRIER             | OFF     | Enable compiler barriers for safety in critical ops (slows performance) |
| ENABLE_CF_BASE_TRUNC          | OFF     | Truncate null-terminated buffers for safety (only applies to encoders) |

---

## Output Directory

You can collect all binaries into a single folder:
```bash
$ cmake -S . -B build_release -DOUTPUT_DIR=bin
```
- All runtime files (library, tests) go into `bin/`.
- If empty, CMake uses the default nested layout.

---

## Build Commands

### Configure & Generate
```bash
$ cmake -S . -B build [options]
```

### Build
```bash
$ cmake --build build --config <BuildType>
```

### Run Tests
```bash
$ ctest --test-dir build --output-on-failure -C <BuildType>
```

---

## Recommended Workflow

### Standard nested layout with DLL copy (dev mode)
```bash
$ cmake -S . -B build
$ cmake --build build
$ ctest --test-dir build --output-on-failure
```

### Unified output folder (simpler for release)
```bash
$ cmake -S . -B build_release -DOUTPUT_DIR=bin -DCMAKE_BUILD_TYPE=Release -DCF_LINK_SHARED=ON
$ cmake --build build_release --config Release
$ ctest --test-dir build_release --output-on-failure -C Release
```

---

## Notes

- Multi-config generators (Visual Studio) require specifying `--config <BuildType>`.
- Copying the DLL next to the test executable ensures runtime loading on Windows.
- Library and test macros are isolated; the library does not see test macros.
- If the build or CMake setup doesn’t work as expected, please be aware this project is new and experimental; feedback or corrections are welcome.