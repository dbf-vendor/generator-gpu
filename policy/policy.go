package policy

import (
	"bufio"
	"github.com/dbf-vendor/generator-gpu/global"
	"github.com/dbf-vendor/generator-gpu/policy/base"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	cracker      string = "hashcat"
	maskFileName string = "maskfile.hcmask"

	argHashcat []string
)

func Main() {
	cracker += global.EXT
	cracker = global.CURRENT_PATH + cracker
	maskFileName = global.CURRENT_PATH + maskFileName

	base.InitBase()

	/* Parse input args */
	var increment bool
	var incrementMin, incrementMax int
	skip := big.NewInt(0)
	limit := big.NewInt(0)

	/* Analyze custom charset */
	var customCharset []string

	var customCharsetMap [4]map[int]string
	var cc map[int]map[int]string
	cc = make(map[int]map[int]string)
	for i := 0; i < 4; i++ {
		customCharsetMap[i] = make(map[int]string)
		cc[base.CHARSETS[i]] = make(map[int]string)
	}

	// Get custom charsets
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "-1":
			i++
			charset := base.ParseChars(os.Args[i])
			for ic := 0; ic < 4; ic++ {
				if len(charset.Chars[base.CHARSETS[ic]]) > 0 {
					switch len(charset.Chars[base.CHARSETS[ic]]) {
					case 1:
						customCharsetMap[0][base.CHARSETS[ic]] = charset.Chars[base.CHARSETS[ic]]
					case base.CHARSETS_LEN[ic]:
						customCharsetMap[0][base.CHARSETS[ic]] = base.GetCharsetName(base.CHARSETS[ic])
					default:
						cc[base.CHARSETS[ic]][0] = charset.Chars[base.CHARSETS[ic]]
					}
				}
			}
		case os.Args[i] == "-2":
			i++
			charset := base.ParseChars(os.Args[i])
			for ic := 0; ic < 4; ic++ {
				if len(charset.Chars[base.CHARSETS[ic]]) > 0 {
					switch len(charset.Chars[base.CHARSETS[ic]]) {
					case 1:
						customCharsetMap[1][base.CHARSETS[ic]] = charset.Chars[base.CHARSETS[ic]]
					case base.CHARSETS_LEN[ic]:
						customCharsetMap[1][base.CHARSETS[ic]] = base.GetCharsetName(base.CHARSETS[ic])
					default:
						cc[base.CHARSETS[ic]][1] = charset.Chars[base.CHARSETS[ic]]
					}
				}
			}
		case os.Args[i] == "-3":
			i++
			charset := base.ParseChars(os.Args[i])
			for ic := 0; ic < 4; ic++ {
				if len(charset.Chars[base.CHARSETS[ic]]) > 0 {
					switch len(charset.Chars[base.CHARSETS[ic]]) {
					case 1:
						customCharsetMap[2][base.CHARSETS[ic]] = charset.Chars[base.CHARSETS[ic]]
					case base.CHARSETS_LEN[ic]:
						customCharsetMap[2][base.CHARSETS[ic]] = base.GetCharsetName(base.CHARSETS[ic])
					default:
						cc[base.CHARSETS[ic]][2] = charset.Chars[base.CHARSETS[ic]]
					}
				}
			}
		case os.Args[i] == "-4":
			i++
			charset := base.ParseChars(os.Args[i])
			for ic := 0; ic < 4; ic++ {
				if len(charset.Chars[base.CHARSETS[ic]]) > 0 {
					switch len(charset.Chars[base.CHARSETS[ic]]) {
					case 1:
						customCharsetMap[3][base.CHARSETS[ic]] = charset.Chars[base.CHARSETS[ic]]
					case base.CHARSETS_LEN[ic]:
						customCharsetMap[3][base.CHARSETS[ic]] = base.GetCharsetName(base.CHARSETS[ic])
					default:
						cc[base.CHARSETS[ic]][3] = charset.Chars[base.CHARSETS[ic]]
					}
				}
			}
		}
	}

	// Classify charsets
	charsetTotal := len(cc[base.CHARSET_D]) + len(cc[base.CHARSET_U]) + len(cc[base.CHARSET_L]) + len(cc[base.CHARSET_S])
	for charsetTotal > 4 {
		// Merge biggest charsets together. TODO: the best way maybe to merge charsets with biggest overlaps
		max := len(cc[base.CHARSETS[0]])
		for ic := 1; ic < 4; ic++ {
			if len(cc[base.CHARSETS[ic]]) > max {
				max = len(cc[base.CHARSETS[ic]])
			}
		}

		for ic := 0; ic < 4; ic++ {
			if len(cc[base.CHARSETS[ic]]) == max {
				customCharset = append(customCharset, base.RemoveDups(cc[base.CHARSETS[ic]][0]+cc[base.CHARSETS[ic]][1]+cc[base.CHARSETS[ic]][2]+cc[base.CHARSETS[ic]][3]))

				for i := 0; i < 4; i++ {
					if len(cc[base.CHARSETS[ic]][i]) > 0 {
						customCharsetMap[i][base.CHARSETS[ic]] = "?" + strconv.Itoa(len(customCharset))
					}
				}

				charsetTotal -= (len(cc[base.CHARSETS[ic]]) - 1)
				delete(cc, base.CHARSETS[ic])
				break
			}
		}
	}

	// Now there at most 4 charsets
	for ic := 0; charsetTotal > 0; ic++ {
		if len(cc[base.CHARSETS[ic]]) > 0 {
			for i := 0; i < 4; i++ {
				if _, ok := cc[base.CHARSETS[ic]][i]; ok {
					customCharset = append(customCharset, base.RemoveDups(cc[base.CHARSETS[ic]][i]))
					customCharsetMap[i][base.CHARSETS[ic]] = "?" + strconv.Itoa(len(customCharset))
					charsetTotal--
				}
			}
			delete(cc, base.CHARSETS[ic])
		}
	}

	/* Get args */
	charsetAssigned := false
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
		case (os.Args[i] == "-1") || (os.Args[i] == "-2") || (os.Args[i] == "-3") || (os.Args[i] == "-4"):
			i++
			if charsetAssigned == false {
				for i, chars := range customCharset {
					argHashcat = append(argHashcat, "-"+strconv.Itoa(i+1), chars)
				}
				charsetAssigned = true
			}
		default:
			argHashcat = append(argHashcat, os.Args[i])
		}
	}

	if len(argHashcat) > 0 {
		maskStr := argHashcat[len(argHashcat)-1]    // Last argument should be mask
		argHashcat = argHashcat[:len(argHashcat)-1] // Remove mask from args

		/* Get mask info */
		for i := 0; i < len(maskStr); i++ {
			if maskStr[i] == '?' {
				i++
				switch {
				case maskStr[i] == 'd':
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_D: "?d",
						},
						Len: map[int]int{
							base.CHARSET_D: 10,
						},
					})
				case maskStr[i] == 'u':
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_U: "?u",
						},
						Len: map[int]int{
							base.CHARSET_U: 26,
						},
					})
				case maskStr[i] == 'l':
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_L: "?l",
						},
						Len: map[int]int{
							base.CHARSET_L: 26,
						},
					})
				case maskStr[i] == 's':
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_S: "?s",
						},
						Len: map[int]int{
							base.CHARSET_S: 33,
						},
					})
				case maskStr[i] == 'a':
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_D: "?d",
							base.CHARSET_U: "?u",
							base.CHARSET_L: "?l",
							base.CHARSET_S: "?s",
						},
						Len: map[int]int{
							base.CHARSET_D: 10,
							base.CHARSET_U: 26,
							base.CHARSET_L: 26,
							base.CHARSET_S: 33,
						},
					})
				case (maskStr[i] == '1') || (maskStr[i] == '2') || (maskStr[i] == '3') || (maskStr[i] == '4'):
					mapIdenx, _ := strconv.Atoi(string(maskStr[i]))
					mapIdenx--
					base.MaskInfo = append(base.MaskInfo, base.CharsetInfo{
						Chars: map[int]string{
							base.CHARSET_D: customCharsetMap[mapIdenx][base.CHARSET_D],
							base.CHARSET_U: customCharsetMap[mapIdenx][base.CHARSET_U],
							base.CHARSET_L: customCharsetMap[mapIdenx][base.CHARSET_L],
							base.CHARSET_S: customCharsetMap[mapIdenx][base.CHARSET_S],
						},
						Len: map[int]int{
							base.CHARSET_D: customCharsetLen(&customCharset, customCharsetMap[mapIdenx][base.CHARSET_D]),
							base.CHARSET_U: customCharsetLen(&customCharset, customCharsetMap[mapIdenx][base.CHARSET_U]),
							base.CHARSET_L: customCharsetLen(&customCharset, customCharsetMap[mapIdenx][base.CHARSET_L]),
							base.CHARSET_S: customCharsetLen(&customCharset, customCharsetMap[mapIdenx][base.CHARSET_S]),
						},
					})
				case maskStr[i] == '?':
					base.MaskInfo = append(base.MaskInfo, base.ParseChars("?"))
				default:
					log.Printf("Invalid mask: %s\n", maskStr)
					os.Exit(1)
				}
			} else {
				base.MaskInfo = append(base.MaskInfo, base.ParseChars(string(maskStr[i])))
			}
		}

		/* Check increment bounds */
		if increment {
			if incrementMin == 0 {
				incrementMin = 1
			} else if incrementMin > len(base.MaskInfo) {
				incrementMin = len(base.MaskInfo)
			}

			if (incrementMax == 0) || (incrementMax > len(base.MaskInfo)) {
				incrementMax = len(base.MaskInfo)
			}

			if incrementMin > incrementMax { // Swap min & max
				incrementMin = incrementMin + incrementMax
				incrementMax = incrementMin - incrementMax
				incrementMin = incrementMin - incrementMax
			}
		} else {
			incrementMin = len(base.MaskInfo)
			incrementMax = len(base.MaskInfo)
		}

		var combination *big.Int
		skipped := false
		zeroInt := big.NewInt(0)
		posMask := make(map[int]int)
		maskPos := make(map[int]int)

		/* Process skip and limit */
		if (skip.Cmp(zeroInt) > 0) || (limit.Cmp(zeroInt) > 0) {
			var l int

			/* Calculate proper incrementMin according to skip */
			if skip.Cmp(zeroInt) > 0 {
				for l = incrementMin; l <= incrementMax; l++ {
					combination = base.PolicyCombination(l, nil)
					if skip.Cmp(combination) < 0 { // skip < combination
						incrementMin = l
						break
					} else {
						skip.Sub(skip, combination)
					}
				}

				if l > incrementMax { // Previus for loop did not reached break, so skip is out of range
					log.Printf("Skip is out of range!\n")
					os.Exit(0)
				}
			}

			/* Calculate proper incrementMax according to limit */
			if limit.Cmp(zeroInt) > 0 {
				combination = base.PolicyCombination(incrementMin, nil)
				combination.Sub(combination, skip)
				if limit.Cmp(combination) > 0 { // limit > (combination - skip)
					limit.Sub(limit, combination) // limit -= (combination - skip)

					for l = incrementMin + 1; l <= incrementMax; l++ {
						combination = base.PolicyCombination(l, nil)
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

			if skip.Cmp(zeroInt) > 0 { // Calculate proper mask for skip
				for l := 0; l < incrementMin; l++ {
					for ic := 0; ic < 4; ic++ {
						if base.MaskInfo[l].Len[base.CHARSETS[ic]] > 0 {
							posMask[l] = base.CHARSETS[ic]
							if _, ok := maskPos[l]; ok == false {
								maskPos[l] = 0
							} else {
								maskPos[l]++
							}
							combination = base.PolicyCombination(incrementMin, &posMask)
							if skip.Cmp(combination) < 0 {
								break
							}
							skip.Sub(skip, combination)
						}
					}
				}
			}

			var argSkipLimit []string
			var keyspace uint64 = 0

			if skip.Cmp(zeroInt) > 0 {
				keyspace = getKeyspace(base.GetMask(incrementMin, &posMask))

				skip.Mul(skip, big.NewInt(0).SetUint64(keyspace))
				skipFloat := big.NewFloat(0).SetInt(skip)
				skipFloat.Quo(skipFloat, big.NewFloat(0).SetInt(combination))
				skipFloat.Int(skip) // Round down
				if skip.Cmp(zeroInt) > 0 {
					argSkipLimit = append(argSkipLimit, "-s", skip.String())
				}
			}

			if limit.Cmp(zeroInt) > 0 {
				if skip.Cmp(zeroInt) > 0 {
					limit.Add(limit, skip)
				}
				if limit.Cmp(combination) < 0 {
					if keyspace <= 0 { // Keyspace is not calculated before
						keyspace = getKeyspace(base.GetMask(incrementMin, &posMask))
					}

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

					incrementMax-- // End execution
				} else if limit.Cmp(combination) == 0 {
					incrementMax-- // End execution
				} else {
					limit.Sub(limit, combination)
				}
			}

			skipped = true
			cmd := exec.Command(cracker, append(argHashcat, append(argSkipLimit, base.GetMask(incrementMin, &posMask))...)...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				log.Printf("%s\n", err)
			}
		}

		if incrementMin <= incrementMax {
			// Initialize maskCharset and maskPos
			maskCharset := make([][]int, incrementMax)
			for l := 0; l < incrementMax; l++ {
				for ic := 0; ic < 4; ic++ {
					if base.MaskInfo[l].Len[base.CHARSETS[ic]] > 0 {
						maskCharset[l] = append(maskCharset[l], base.CHARSETS[ic])
					}
				}
				if _, ok := maskPos[l]; ok == false {
					maskPos[l] = 0
				}
			}

			if skipped {
				base.NextMaskPos(&incrementMin, &incrementMax, &maskPos, &maskCharset)
			}

			maskFile, err := os.Create(maskFileName)
			if err != nil {
				log.Printf("%s\n", err)
				os.Exit(1)
			}

			maskWriter := bufio.NewWriter(maskFile)

			if limit.Cmp(zeroInt) > 0 { // Should apply limit
				var mask []string
				for i := incrementMin; i <= incrementMax; i++ {
					mask = make([]string, i)
					for l := 0; l < i; l++ {
						mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]
					}

					for {
						l := i - 1
						for maskPos[l] < len(maskCharset[l]) {
							mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]

							maskCheck := 0
							for j := 0; j < i; j++ {
								maskCheck |= maskCharset[j][maskPos[j]]
							}
							if (maskCheck & 15) == 15 { // Valid mask
								combination.SetInt64(1)
								for j := 0; j < i; j++ {
									combination.Mul(combination, big.NewInt(int64(base.MaskInfo[j].Len[maskCharset[j][maskPos[j]]])))
								}
								if limit.Cmp(combination) < 0 { // Calculate limit and execute it separately
									l = 0 // Break parent loop
									incrementMax = i
									i++ // Break parent of parent loop
									break
								} else { // Is in limit range
									maskWriter.WriteString(strings.Join(mask, "") + "\n")
									limit.Sub(limit, combination)

									if limit.Cmp(zeroInt) == 0 {
										l = 0                // Break parent loop
										i = incrementMax + 1 // Break parent of parent loop
										break
									}
								}
							}

							maskPos[l]++
						}

						for l > 0 {
							maskPos[l] = 0
							mask[l] = base.MaskInfo[l].Chars[maskCharset[l][0]]

							l--
							maskPos[l]++
							if maskPos[l] < len(maskCharset[l]) {
								mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]
								l++ // ++ for last break check (l == 0)
								break
							}
						}
						if l == 0 {
							break
						}
					}
				}

				if limit.Cmp(zeroInt) > 0 { // Calculate limit and execute it separately
					keyspace := getKeyspace(strings.Join(mask, ""))

					limit.Mul(limit, big.NewInt(0).SetUint64(keyspace))
					limitFloat := big.NewFloat(0).SetInt(limit)
					limitFloat.Quo(limitFloat, big.NewFloat(0).SetInt(combination))
					_, acc := limitFloat.Int(limit)
					if acc == big.Below {
						limit.Add(limit, big.NewInt(1)) // Round up
					}
					if limit.Cmp(zeroInt) > 0 {
						cmd := exec.Command(cracker, append(argHashcat, "-l", limit.String(), strings.Join(mask, ""))...)
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
						err := cmd.Run()
						if err != nil {
							log.Printf("%s\n", err)
						}
					}
				}
			} else { // There is no limit
				for i := incrementMin; i <= incrementMax; i++ {
					mask := make([]string, i)
					for l := 0; l < i; l++ {
						mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]
					}

					for {
						l := i - 1
						for maskPos[l] < len(maskCharset[l]) {
							mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]

							maskCheck := 0
							for j := 0; (j < i) && ((maskCheck & 15) != 15); j++ {
								maskCheck |= maskCharset[j][maskPos[j]]
							}
							if (maskCheck & 15) == 15 { // Valid mask
								maskWriter.WriteString(strings.Join(mask, "") + "\n")
							}

							maskPos[l]++
						}

						for l > 0 {
							maskPos[l] = 0
							mask[l] = base.MaskInfo[l].Chars[maskCharset[l][0]]

							l--
							maskPos[l]++
							if maskPos[l] < len(maskCharset[l]) {
								mask[l] = base.MaskInfo[l].Chars[maskCharset[l][maskPos[l]]]
								l++ // ++ for last break check (l == 0)
								break
							}
						}
						if l == 0 {
							break
						}
					}
				}
			}

			maskWriter.Flush()

			maskFile.Close()

			cmd := exec.Command(cracker, append(argHashcat, maskFileName)...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				log.Printf("%s\n", err)
			}

			os.Remove(maskFileName)
		}
	} else {
		cmd := exec.Command(cracker)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			log.Printf("%s\n", err)
		}
	}
}

func customCharsetLen(customCharset *[]string, charset string) int {
	if len(charset) < 1 {
		return 0
	}

	switch charset {
	case "?1":
		return len((*customCharset)[0])
	case "?2":
		return len((*customCharset)[1])
	case "?3":
		return len((*customCharset)[2])
	case "?4":
		return len((*customCharset)[3])
	case "?d":
		return 10
	case "?u":
		return 26
	case "?l":
		return 26
	case "?s":
		return 33
	default:
		return 1
	}
}

func getKeyspace(mask string) uint64 {
	var keyspace uint64

	cmd := exec.Command(cracker, append(argHashcat, "--quiet", "--keyspace", mask)...)
	cmd.Stderr = os.Stderr

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
