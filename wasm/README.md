# disasm64 — WebAssembly playground

A browser front-end for the disassembler. `disasm64_wasm.cpp` exports `d64_disasm(hex,
base, att)`; `playground.html` is a self-contained page that calls it.

## Build

Needs the [Emscripten SDK](https://emscripten.org) on `PATH`:

```sh
source /path/to/emsdk/emsdk_env.sh
./build.sh          # -> disasm64.js + disasm64.wasm
```

Then serve the folder (the browser won't fetch `.wasm` over `file://`):

```sh
python -m http.server
# open http://localhost:8000/playground.html
```

The build artifacts (`disasm64.js`, `disasm64.wasm`) are not checked in — run `build.sh`.
