#!/usr/bin/env bash
# Build the WebAssembly playground. Requires the Emscripten SDK (https://emscripten.org)
# on PATH (`source emsdk_env.sh`). Produces disasm64.js + disasm64.wasm next to this script.
set -e
cd "$(dirname "$0")"

emcc -O3 -std=c++17 -I../include \
    ../src/prefix.cpp ../src/operand.cpp ../src/decode.cpp \
    ../src/format_intel.cpp ../src/format_att.cpp ../src/relocate.cpp \
    ../src/encode.cpp ../src/analysis.cpp disasm64_wasm.cpp \
    -s EXPORTED_FUNCTIONS='["_d64_disasm","_malloc","_free"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
    -s MODULARIZE=1 -s EXPORT_NAME=Disasm64Module \
    -s ALLOW_MEMORY_GROWTH=1 \
    -o disasm64.js

echo "built disasm64.js + disasm64.wasm -- open playground.html"
