export async function loadWasmVerifier() {
  return {
    ready: true,
    engine: "arkhe-mobile-verify-wasm",
  };
}
