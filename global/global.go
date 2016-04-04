package global

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	GENERATOR_GENERAL = 1
	GENERATOR_POLICY  = 2
)

var (
	GENERATOR    int
	CURRENT_PATH string
	EXT          string
)

func InitGlobal() {
	// Set current path
	absPath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err == nil {
		CURRENT_PATH = absPath + string(os.PathSeparator)
	} else {
		CURRENT_PATH = "." + string(os.PathSeparator)
	}

	// Set extension of executable
	switch runtime.GOOS { // Get OS
	case "linux":
		EXT = ".bin"
	case "windows":
		EXT = ".exe"
	case "darwin":
		EXT = ".app"
	default:
		EXT = ""
	}
}
