package main

import (
	"fmt"
	"os"
	"runtime"

	"cryptclient/deps"
)

// refuseElevated stops the commands that open the storage when the program runs with full administrator
// rights on Windows. SSHFS-Win cannot write from such a token (the server refuses the ownership change
// Windows asks for), so every save would fail with "access denied". The warning says what to do instead.
func refuseElevated() {
	if runtime.GOOS != "windows" || !deps.IsAdmin() {
		return
	}
	fmt.Println(elevatedWarning)
	os.Exit(1)
}

const elevatedWarning = `This window was started "as administrator". The storage cannot be written to that way,
so files would fail to save with "access denied".
Close this window and start the client again normally (without "Run as administrator").`
