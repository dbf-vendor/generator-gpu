package base

import (
	"math/big"
	"strings"
)

const (
	CHARSET_D = 1
	CHARSET_U = 2
	CHARSET_L = 4
	CHARSET_S = 8

	CHARS_D = "0123456789"
	CHARS_U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CHARS_L = "abcdefghijklmnopqrstuvwxyz"
	CHARS_S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

var CHARSETS, CHARSETS_LEN [4]int

type CharsetInfo struct {
	Chars map[int]string
	Len   map[int]int
}

var MaskInfo []CharsetInfo

func (charset CharsetInfo) count(charsetMask int) uint {
	var cnt uint

	if (charsetMask & CHARSET_D) == CHARSET_D {
		if charset.Len[CHARSET_D] > 0 {
			cnt += uint(charset.Len[CHARSET_D])
		}
	}

	if (charsetMask & CHARSET_U) == CHARSET_U {
		if charset.Len[CHARSET_U] > 0 {
			cnt += uint(charset.Len[CHARSET_U])
		}
	}

	if (charsetMask & CHARSET_L) == CHARSET_L {
		if charset.Len[CHARSET_L] > 0 {
			cnt += uint(charset.Len[CHARSET_L])
		}
	}

	if (charsetMask & CHARSET_S) == CHARSET_S {
		if charset.Len[CHARSET_S] > 0 {
			cnt += uint(charset.Len[CHARSET_S])
		}
	}

	return cnt
}

func InitBase() {
	CHARSETS[0] = CHARSET_D
	CHARSETS[1] = CHARSET_U
	CHARSETS[2] = CHARSET_L
	CHARSETS[3] = CHARSET_S

	CHARSETS_LEN[0] = len(CHARS_D)
	CHARSETS_LEN[1] = len(CHARS_U)
	CHARSETS_LEN[2] = len(CHARS_L)
	CHARSETS_LEN[3] = len(CHARS_S)
}

func GetCharsetName(id int) string {
	switch id {
	case CHARSET_D:
		return "?d"
	case CHARSET_U:
		return "?u"
	case CHARSET_L:
		return "?l"
	case CHARSET_S:
		return "?s"
	default:
		return ""
	}
}

func combination(maskLen int, posMask *map[int]int, charsetMask int) *big.Int {
	cnt := big.NewInt(1)

	zeroInt := big.NewInt(0)
	for l := 0; l < maskLen; l++ {
		mask := charsetMask
		if posMask != nil {
			if _, ok := (*posMask)[l]; ok {
				mask &= (*posMask)[l]
			}
		}

		cnt.Mul(cnt, big.NewInt(int64(MaskInfo[l].count(mask))))
		if cnt.Cmp(zeroInt) == 0 {
			break
		}
	}

	return cnt
}

func PolicyCombination(maskLen int, posMask *map[int]int) *big.Int {
	result := big.NewInt(0)

	result.Add(result, combination(maskLen, posMask, CHARSET_D+CHARSET_U+CHARSET_L+CHARSET_S))

	result.Sub(result, combination(maskLen, posMask, CHARSET_D+CHARSET_U+CHARSET_L))
	result.Sub(result, combination(maskLen, posMask, CHARSET_D+CHARSET_U+CHARSET_S))
	result.Sub(result, combination(maskLen, posMask, CHARSET_D+CHARSET_L+CHARSET_S))
	result.Sub(result, combination(maskLen, posMask, CHARSET_U+CHARSET_L+CHARSET_S))

	result.Add(result, combination(maskLen, posMask, CHARSET_D+CHARSET_U))
	result.Add(result, combination(maskLen, posMask, CHARSET_D+CHARSET_L))
	result.Add(result, combination(maskLen, posMask, CHARSET_D+CHARSET_S))
	result.Add(result, combination(maskLen, posMask, CHARSET_U+CHARSET_L))
	result.Add(result, combination(maskLen, posMask, CHARSET_U+CHARSET_S))
	result.Add(result, combination(maskLen, posMask, CHARSET_L+CHARSET_S))

	result.Sub(result, combination(maskLen, posMask, CHARSET_D))
	result.Sub(result, combination(maskLen, posMask, CHARSET_U))
	result.Sub(result, combination(maskLen, posMask, CHARSET_L))
	result.Sub(result, combination(maskLen, posMask, CHARSET_S))

	return result
}

func ParseChars(chars string) CharsetInfo {
	var d, u, l, s string

	chars = strings.Replace(chars, "?d", CHARS_D, -1)
	chars = strings.Replace(chars, "?u", CHARS_U, -1)
	chars = strings.Replace(chars, "?l", CHARS_L, -1)
	chars = strings.Replace(chars, "?s", CHARS_S, -1)
	chars = strings.Replace(chars, "?a", CHARS_D+CHARS_U+CHARS_L+CHARS_S, -1)
	chars = strings.Replace(chars, "??", "?", -1)

	chars = RemoveDups(chars)

	for _, c := range chars {
		switch {
		case (47 < c) && (c < 58): // 48 <= digit <= 57
			d += string(c)
		case (64 < c) && (c < 91): // 65 <= upper <= 90
			u += string(c)
		case (96 < c) && (c < 123): // 97 <= lower <= 122
			l += string(c)
		case (31 < c) && (c < 127): // 32 <= printable <= 126
			s += string(c)
		}
	}

	var charset CharsetInfo
	charset.Chars = make(map[int]string)
	charset.Len = make(map[int]int)

	if len(d) > 0 {
		charset.Chars[CHARSET_D] = d
		charset.Len[CHARSET_D] = len(d)
	}

	if len(u) > 0 {
		charset.Chars[CHARSET_U] = u
		charset.Len[CHARSET_U] = len(u)
	}

	if len(l) > 0 {
		charset.Chars[CHARSET_L] = l
		charset.Len[CHARSET_L] = len(l)
	}

	if len(s) > 0 {
		charset.Chars[CHARSET_S] = s
		charset.Len[CHARSET_S] = len(s)
	}

	return charset
}

func RemoveDups(str string) string {
	for _, c := range str {
		cnt := strings.Count(str, string(c))
		if cnt > 1 {
			str = strings.Replace(str, string(c), "", cnt-1)
		}
	}

	return str
}

func NextMaskPos(min *int, max *int, maskPos *map[int]int, maskCharset *[][]int) bool {
	(*maskPos)[*min-1]++

	for ; *min <= *max; *min++ {
		for {
			l := *min - 1
			for (*maskPos)[l] < len((*maskCharset)[l]) {
				maskCheck := 0
				for j := 0; (j < *min) && ((maskCheck & 15) != 15); j++ {
					maskCheck |= (*maskCharset)[j][(*maskPos)[j]]
				}
				if (maskCheck & 15) == 15 { // Valid mask
					return true
				}

				(*maskPos)[l]++
			}

			for l > 0 {
				(*maskPos)[l] = 0

				l--
				(*maskPos)[l]++
				if (*maskPos)[l] < len((*maskCharset)[l]) {
					l++ // ++ for last break check (l == 0)
					break
				}
			}
			if l == 0 {
				break
			}
		}
	}

	return false
}

func GetMask(maskLen int, posMask *map[int]int) string {
	mask := ""

	for l := 0; l < maskLen; l++ {
		if posMask != nil {
			if _, ok := (*posMask)[l]; ok {
				mask += MaskInfo[l].Chars[(*posMask)[l]]
				continue
			}
		}

		for ic := 0; ic < 4; ic++ {
			if MaskInfo[l].Len[CHARSETS[ic]] > 0 {
				mask += MaskInfo[l].Chars[CHARSETS[ic]]
				break
			}
		}
	}

	return mask
}
