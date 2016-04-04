package general

import (
	"bufio"
	"github.com/dbf-vendor/generator-gpu/global"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	cracker string = "hashcat"

	argHashcat, maskPos []string
	lenMaskPos          []int
)

func Main() {
	cracker += global.EXT
	cracker = global.CURRENT_PATH + cracker

	/* Parse input args */
	var increment bool
	var incrementMin, incrementMax int
	var c1, c2, c3, c4 string
	skip := big.NewInt(0)
	limit := big.NewInt(0)

	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "-i":
			increment = true
		case os.Args[i] == "--increment-min":
			i++
			incrementMin, _ = strconv.Atoi(os.Args[i])
		case strings.HasPrefix(os.Args[i], "--increment-min="):
			incrementMin, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(os.Args[i], "--increment-min=")))
		case os.Args[i] == "--increment-max":
			i++
			incrementMax, _ = strconv.Atoi(os.Args[i])
		case strings.HasPrefix(os.Args[i], "--increment-max="):
			incrementMax, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(os.Args[i], "--increment-max=")))
		case os.Args[i] == "-s":
			i++
			_, ok := skip.SetString(os.Args[i], 10)
			if ok == false {
				skip.SetUint64(0)
			}
		case os.Args[i] == "-l":
			i++
			_, ok := limit.SetString(os.Args[i], 10)
			if ok == false {
				limit.SetUint64(0)
			}
		case os.Args[i] == "-1":
			i++
			c1 = os.Args[i]
			argHashcat = append(argHashcat, "-1", os.Args[i])
		case os.Args[i] == "-2":
			i++
			c2 = os.Args[i]
			argHashcat = append(argHashcat, "-2", os.Args[i])
		case os.Args[i] == "-3":
			i++
			c3 = os.Args[i]
			argHashcat = append(argHashcat, "-3", os.Args[i])
		case os.Args[i] == "-4":
			i++
			c4 = os.Args[i]
			argHashcat = append(argHashcat, "-4", os.Args[i])
		default:
			argHashcat = append(argHashcat, os.Args[i])
		}
	}

	if len(argHashcat) > 0 {
		mask := argHashcat[len(argHashcat)-1]       // Last argument should be mask
		argHashcat = argHashcat[:len(argHashcat)-1] // Remove mask from args

		/* Calculate number of characters in each mask position */
		for i := 0; i < len(mask); i++ {
			if mask[i] == '?' {
				i++
				switch {
				case mask[i] == 'l':
					maskPos = append(maskPos, "?l")
					lenMaskPos = append(lenMaskPos, 26)
				case mask[i] == 'u':
					maskPos = append(maskPos, "?u")
					lenMaskPos = append(lenMaskPos, 26)
				case mask[i] == 'd':
					maskPos = append(maskPos, "?d")
					lenMaskPos = append(lenMaskPos, 10)
				case mask[i] == 's':
					maskPos = append(maskPos, "?s")
					lenMaskPos = append(lenMaskPos, 33)
				case mask[i] == 'a':
					maskPos = append(maskPos, "?a")
					lenMaskPos = append(lenMaskPos, 95)
				case mask[i] == '1':
					maskPos = append(maskPos, "?1")
					if len(c1) > 1 {
						lenMaskPos = append(lenMaskPos, len(c1)-strings.Count(c1, "??"))
					} else {
						lenMaskPos = append(lenMaskPos, 1)
					}
				case mask[i] == '2':
					maskPos = append(maskPos, "?2")
					if len(c2) > 1 {
						lenMaskPos = append(lenMaskPos, len(c2)-strings.Count(c2, "??"))
					} else {
						lenMaskPos = append(lenMaskPos, 1)
					}
				case mask[i] == '3':
					maskPos = append(maskPos, "?3")
					if len(c3) > 1 {
						lenMaskPos = append(lenMaskPos, len(c3)-strings.Count(c3, "??"))
					} else {
						lenMaskPos = append(lenMaskPos, 1)
					}
				case mask[i] == '4':
					maskPos = append(maskPos, "?4")
					if len(c4) > 1 {
						lenMaskPos = append(lenMaskPos, len(c4)-strings.Count(c4, "??"))
					} else {
						lenMaskPos = append(lenMaskPos, 1)
					}
				case mask[i] == '?':
					maskPos = append(maskPos, "??")
					lenMaskPos = append(lenMaskPos, 1)
				default:
					log.Printf("Invalid mask: %s\n", mask)
					os.Exit(1)
				}
			} else {
				maskPos = append(maskPos, string(mask[i]))
				lenMaskPos = append(lenMaskPos, 1)
			}
		}

		/* Check increment bounds */
		if increment {
			if incrementMin == 0 {
				incrementMin = 1
			} else if incrementMin > len(lenMaskPos) {
				incrementMin = len(lenMaskPos)
			}

			if (incrementMax == 0) || (incrementMax > len(lenMaskPos)) {
				incrementMax = len(lenMaskPos)
			}

			if incrementMin > incrementMax { // Swap min & max
				incrementMin = incrementMin + incrementMax
				incrementMax = incrementMin - incrementMax
				incrementMin = incrementMin - incrementMax
			}
		} else {
			incrementMin = len(lenMaskPos)
			incrementMax = len(lenMaskPos)
		}

		/* Check for keyspace calculation */
		if zeroInt := big.NewInt(0); (skip.Cmp(zeroInt) > 0) || (limit.Cmp(zeroInt) > 0) {
			var l int

			/* Calculate proper incrementMin according to skip */
			if skip.Cmp(zeroInt) > 0 {
				for l = incrementMin; l <= incrementMax; l++ {
					combination := getCombination(l)
					if skip.Cmp(combination) < 0 { // skip < combination
						incrementMin = l
						break
					} else {
						skip.Sub(skip, combination)
					}
				}

				if l > incrementMax { // Previus for loop did not reached break, so skip is out of range
					os.Exit(0)
				}
			}

			/* Calculate proper incrementMax according to limit */
			if limit.Cmp(zeroInt) > 0 {
				combination := getCombination(incrementMin)
				combination.Sub(combination, skip)
				if limit.Cmp(combination) > 0 { // limit > (combination - skip)
					limit.Sub(limit, combination) // limit -= (combination - skip)

					for l = incrementMin + 1; l <= incrementMax; l++ {
						combination := getCombination(l)
						if limit.Cmp(combination) > 0 { // limit > combination
							limit.Sub(limit, combination)
						} else {
							incrementMax = l
							if limit.Cmp(combination) == 0 {
								limit.SetUint64(0) // Limit contains whole range, no need to use it
							}
							break
						}
					}

					if l > incrementMax {
						limit.SetUint64(0) // Limit is out of range, so ignore it
					}
				} else {
					incrementMax = incrementMin
					if limit.Cmp(combination) == 0 { // limit == (combination - skip)
						limit.SetUint64(0) // Limit contains whole range, no need to use it
					}
				}
			}

			/* Apply skip and limit */
			if skip.Cmp(zeroInt) > 0 {
				var argSkipLimit []string

				keyspace := getKeyspace(incrementMin)
				combination := getCombination(incrementMin)

				skip.Mul(skip, big.NewInt(0).SetUint64(keyspace))
				skipFloat := big.NewFloat(0).SetInt(skip)
				skipFloat.Quo(skipFloat, big.NewFloat(0).SetInt(combination))
				skipFloat.Int(skip) // Round down
				if skip.Cmp(zeroInt) > 0 {
					argSkipLimit = append(argSkipLimit, "-s", skip.String())
				}

				if (incrementMin == incrementMax) && (limit.Cmp(zeroInt) > 0) {
					limit.Mul(limit, big.NewInt(0).SetUint64(keyspace))
					limitFloat := big.NewFloat(0).SetInt(limit)
					limitFloat.Quo(limitFloat, big.NewFloat(0).SetInt(combination))
					_, acc := limitFloat.Int(limit)
					if acc == big.Below {
						limit.Add(limit, big.NewInt(1)) // Round up
					}
					if limit.Cmp(zeroInt) > 0 {
						argSkipLimit = append(argSkipLimit, "-l", limit.String())
						limit.SetUint64(0) // Limit applied here, do not apply it later
					}

					incrementMax--
				}

				cmd := exec.Command(cracker, append(argHashcat, append(argSkipLimit, strings.Join(maskPos[:incrementMin], ""))...)...)
				cmd.Stdout = os.Stdout
				err := cmd.Run()
				if err != nil {
					log.Printf("%s\n", err)
				}

				incrementMin++
			}

			if limit.Cmp(zeroInt) > 0 {
				var argSkipLimit []string

				keyspace := getKeyspace(incrementMax)
				combination := getCombination(incrementMax)

				limit.Mul(limit, big.NewInt(0).SetUint64(keyspace))
				limitFloat := big.NewFloat(0).SetInt(limit)
				limitFloat.Quo(limitFloat, big.NewFloat(0).SetInt(combination))
				_, acc := limitFloat.Int(limit)
				if acc == big.Below {
					limit.Add(limit, big.NewInt(1)) // Round up
				}
				argSkipLimit = append(argSkipLimit, "-l", limit.String())

				cmd := exec.Command(cracker, append(argHashcat, append(argSkipLimit, strings.Join(maskPos[:incrementMax], ""))...)...)
				cmd.Stdout = os.Stdout
				err := cmd.Run()
				if err != nil {
					log.Printf("%s\n", err)
				}

				incrementMax--
			}
		}

		for i := incrementMin; i <= incrementMax; i++ {
			cmd := exec.Command(cracker, append(argHashcat, strings.Join(maskPos[:i], ""))...)
			cmd.Stdout = os.Stdout
			err := cmd.Run()
			if err != nil {
				log.Printf("%s\n", err)
			}
		}
	} else {
		cmd := exec.Command(cracker)
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			log.Printf("%s\n", err)
		}
	}
}

func getCombination(lenMask int) *big.Int {
	combination := big.NewInt(1)
	for i := 0; i < lenMask; i++ {
		combination.Mul(combination, big.NewInt(int64(lenMaskPos[i])))
	}

	return combination
}

func getKeyspace(lenMask int) uint64 {
	var keyspace uint64

	cmd := exec.Command(cracker, append(argHashcat, "--quiet", "--keyspace", strings.Join(maskPos[:lenMask], ""))...)

	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}

	err = cmd.Start()
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}

	cmdScanner := bufio.NewScanner(cmdOut)
	cmdScanner.Split(bufio.ScanLines)
	for cmdScanner.Scan() {
		// Get keyspace from line
		keyspace, err = strconv.ParseUint(cmdScanner.Text(), 10, 64)
		if err == nil {
			break // Quit for loop
		}
	}
	err = cmdScanner.Err()
	if err != nil {
		log.Printf("%s\n", err)
	}

	err = cmd.Wait()
	if err != nil {
		log.Printf("%s\n", err)
	}

	if keyspace < 1 {
		log.Printf("keyspace not determined!\n")
		os.Exit(1)
	}

	return keyspace
}
