# ML-KEM (mlkem-native → WASM) Setup (Client/Server Repo)

Repo structure (same level):
<repo-root>/
client/
server/
wasm/ # provided by THIS repo (contains shim + build helpers)
mlkem-native/ # cloned by developer (external repo)


This project requires building **WASM artifacts** from `mlkem-native` and a provided `wasm/` folder (from this repo).
The `wasm/` folder must be copied into `mlkem-native` right after cloning.

---

## 1) Prerequisites (WSL2 recommended)

- Git
- Node.js (recommended Node 20 LTS) + npm
- Ubuntu/WSL build tools:
```bash
sudo apt update
sudo apt install -y git build-essential python3 cmake
2) Clone THIS repo
git clone <THIS_REPO_URL>
cd <THIS_REPO_FOLDER>
Install dependencies:

cd client
npm ci || npm install
cd ..

cd server
if [ -f package.json ]; then npm ci || npm install; fi
cd ..
3) Clone mlkem-native at the SAME LEVEL as client/server/wasm
From <repo-root>:

git clone https://github.com/pq-code-package/mlkem-native.git mlkem-native
After this, you should have:

<repo-root>/mlkem-native

4) Copy the provided wasm/ folder into mlkem-native (IMMEDIATELY after cloning)
From <repo-root>:

Linux / WSL
# If mlkem-native/wasm already exists, replace it with the repo-provided one:
rm -rf mlkem-native/wasm
cp -a wasm mlkem-native/
This must result in:

<repo-root>/mlkem-native/wasm/

and inside it, the required shim file:

<repo-root>/mlkem-native/wasm/shim_mlkem768.c

Windows PowerShell (if not using WSL)
Remove-Item -Recurse -Force .\mlkem-native\wasm -ErrorAction SilentlyContinue
Copy-Item -Recurse -Force .\wasm .\mlkem-native\
5) Install Emscripten (emsdk) for building WASM
From <repo-root>:

mkdir -p third_party
cd third_party
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk

./emsdk install latest
./emsdk activate latest

# Must run in every new shell before building WASM:
source ./emsdk_env.sh

emcc -v
cd ../../
6) Build mlkem.js + mlkem.wasm
Activate emsdk environment (every session):

cd third_party/emsdk
source ./emsdk_env.sh
cd ../../
Build from inside the copied folder:

cd mlkem-native/wasm
mkdir -p out
Generic build template (may need adjustment depending on mlkem-native source layout):

SRC_ROOT=".."

SOURCES=$(find "$SRC_ROOT" \
  -type d \( -name test -o -name tests -o -name example -o -name examples -o -name bench -o -name benchmarks \) -prune -false \
  -o -name "*.c" -print)

emcc $SOURCES shim_mlkem768.c \
  -O3 \
  -I"$SRC_ROOT" \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sENVIRONMENT=web \
  -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -Wl,--no-entry \
  -o out/mlkem.js
Expected outputs:

<repo-root>/mlkem-native/wasm/out/mlkem.js

<repo-root>/mlkem-native/wasm/out/mlkem.wasm

7) Copy WASM artifacts into the client (based on your client loader path)
First, find how the client loads mlkem.js / mlkem.wasm:

cd <repo-root>
grep -R "mlkem\.wasm\|mlkem\.js" -n client | head -n 50
If your client loads from /wasm/... (common stable approach), do:

mkdir -p client/public/wasm
cp mlkem-native/wasm/out/mlkem.js client/public/wasm/
cp mlkem-native/wasm/out/mlkem.wasm client/public/wasm/
8) Run
Client:

cd client
npm run dev
Server:

cd ../server
npm run dev || npm run start
9) Troubleshooting: WASM missing HEAPU8
If you see:

Error: WASM missing HEAPU8 (from mlkem.js / called by App.jsx)

Checklist:

DevTools → Network: confirm mlkem.wasm returns 200 OK (not 404)

Ensure ML-KEM init is awaited before calling any function

Rebuild with -sEXPORTED_RUNTIME_METHODS='["HEAPU8"]' (already included above)

Hard refresh / clear cache