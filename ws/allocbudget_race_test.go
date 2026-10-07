//go:build race

package ws

// raceDetectorOn reports that the binary is built with the race detector.
// The flate reader's per-message allocation count is inflated by the race
// instrumentation, so the decompression allocation budget is pinned only on
// the non-race test run; under -race the assertion is skipped.
func raceDetectorOn() bool { return true }
