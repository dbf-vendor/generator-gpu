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
			os.Args = append(os.Args[:i], os.Args[i+1:]...) // Remove from args
		case "--generator-policy":
			global.GENERATOR = global.GENERATOR_POLICY
			os.Args = append(os.Args[:i], os.Args[i+1:]...) // Remove from args
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
