//go:build !race

package ws

// raceDetectorOn reports that the binary is built without the race detector,
// so the flate-based decompression allocation budget is reliable.
func raceDetectorOn() bool { return false }
