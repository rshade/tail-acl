//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal best-effort turns on ANSI escape processing for the
// Windows console. Unlike Unix terminals, the legacy Windows console does not
// interpret SGR escapes unless ENABLE_VIRTUAL_TERMINAL_PROCESSING is set on the
// stdout handle, so raw escapes would otherwise print as garbage.
//
// Every failure is silently ignored on purpose: this runs before the logger
// exists, the console may not be a real console (a pipe or file has no mode to
// set), and a redirected stdout is exactly the case where color is already
// disabled by colorEnabled. The downside of a failed enable is uncolored
// output, never corrupted output.
func enableVirtualTerminal() {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
