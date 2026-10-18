// Preloaded into the shared test server by the Go tests (node --require <this> ../test-server/server.mjs ...).
// The server exits when its stdin closes, which happens when the Go test binary ends, even when it is killed,
// so no test server outlives its tests.
process.stdin.on('end', () => process.exit(0));
process.stdin.on('error', () => process.exit(0));
process.stdin.resume();
