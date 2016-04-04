package main

import (
	"github.com/dbf-vendor/generator-gpu/general"
	"github.com/dbf-vendor/generator-gpu/global"
	"github.com/dbf-vendor/generator-gpu/policy"
	"os"
)

func main() {
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--generator-general":
			global.GENERATOR = global.GENERATOR_GENERAL
		case "--generator-policy":
			global.GENERATOR = global.GENERATOR_POLICY
		}
		if global.GENERATOR > 0 {
			break
		}
	}

	global.InitGlobal()

	switch global.GENERATOR {
	case global.GENERATOR_POLICY:
		policy.Main()
	default:
		general.Main()
	}
}
