//go:build !windows

package main

// enableVirtualTerminal is a no-op everywhere but Windows: Unix terminals
// interpret ANSI SGR escapes natively, so nothing needs enabling. Kept as a
// build-tagged pair (see color_windows.go) so main() calls one name on every OS.
func enableVirtualTerminal() {}
