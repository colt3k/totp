package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"encoding/base32"
	"encoding/binary"
	log "github.com/colt3k/nglog/ng"
	"github.com/colt3k/utils/crypt"
	"github.com/colt3k/utils/crypt/encrypt/argon2id"
	"math/big"
	"regexp"
	"strings"
	"time"
)

/*
Seed : creates a derived seed of 16, 26 or 32 chars; default 32
*/
func Seed(size int) ([]byte, error) {
	if size != 16 && size != 26 && size != 32 {
		size = 32
	}
	var salt []byte
	salt = crypt.GenSalt(salt, 16)
	tkn, err := generateToken(32)
	if err != nil {
		log.Logf(log.ERROR, "issue creating token %v", err)
		return nil, err
	}
	dk, _, _ := argon2id.Key([]byte(tkn), salt, 32)
	dkHash := base32.StdEncoding.EncodeToString(dk)
	//log.Logf(log.INFO, "%v", dkHash[:size])
	return []byte(dkHash[:size]), nil
}

func generateToken(size int) (string, error) {
	length := 26
	if size > 16 && size <= 32 {
		length = size
	}
	chars := ""
	chars = chars + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	chars = chars + "0123456789"

	str := ""
	counter := 0
	valid := false
	for {
		counter++
		buf := make([]byte, length)
		for i := 0; i < length; i++ {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}
			buf[i] = chars[num.Int64()]
		}
		str = string(buf)
		//log.Logf(log.INFO, "repeated %v - last gend '%v'", counter, str)
		valid = validate(false, true, true, "", str)
		if valid {
			break
		}
	}
	return str, nil
}

func validate(lower, upper, digit bool, specialChars, str string) bool {
	valid := false
	if lower && regexp.MustCompile(`[a-z]`).MatchString(str) {
		valid = true
	} else if lower {
		valid = false
	}
	if upper && regexp.MustCompile(`[A-Z]`).MatchString(str) {
		valid = true
	} else if upper {
		valid = false
	}
	if digit && regexp.MustCompile(`\d`).MatchString(str) {
		valid = true
	} else if digit {
		valid = false
	}
	mustComp := ""
	if len(specialChars) > 0 {
		mustComp = `[` + specialChars + `]`
	}
	if len(specialChars) > 0 && regexp.MustCompile(mustComp).MatchString(str) {
		valid = true
	} else if len(specialChars) > 0 {
		valid = false
	}
	return valid
}

// GenerateOTP returns OTP and time until expiration
func GenerateOTP(seed []byte) (uint32, uint32, uint32, int) {
	t := time.Now()
	now := t.Unix()
	// diff of seconds between now and 30 or now and next minute
	sec := t.Second()
	var exp int
	if sec < 30 {
		exp = 30 - sec
	} else if sec > 30 {
		exp = 60 - sec
	}

	totpCodePrev := generateTOTP(seed, now-30)
	totpCode := generateTOTP(seed, now)
	totpCodeNext := generateTOTP(seed, now+30)
	return totpCodePrev, totpCode, totpCodeNext, exp
}

// https://rednafi.com/go/totp_client/
func generateTOTP(secretKey []byte, timestamp int64) uint32 {
	// The base32 encoded secret key string is decoded to a byte slice
	//    Trim whitespace and convert the base32 encoded secret key string to uppercase
	base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretKeyUpper := strings.ToUpper(strings.TrimSpace(string(secretKey))) // preprocess
	secretBytes, _ := base32Decoder.DecodeString(secretKeyUpper)            // decode

	// The truncated timestamp / 30 is converted to an 8-byte big-endian
	// unsigned integer slice
	//    Decode the preprocessed secret key from base32 to a byte slice
	//    Get the current timestamp, divide by 30, and convert it to an 8-byte big-endian unsigned integer
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp)/30)

	// The timestamp bytes are concatenated with the decoded secret key
	// bytes. Then a 20-byte SHA-1 hash is calculated from the byte slice
	//   Concatenate the timestamp integer bytes with the decoded secret key bytes
	//   Hash the concatenated bytes to get a 20-byte SHA-1 digest
	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(timeBytes) // Concat the timestamp byte slice
	h := hash.Sum(nil)    // Calculate 20-byte SHA-1 digest

	// AND the SHA-1 with 0x0F (15) to get a single-digit offset
	//   Get the last byte of the SHA-1 digest and AND it with 0x0F (15) to mask off all but the last 4 bits to get an offset index from 0-15
	offset := h[len(h)-1] & 0x0F

	// Truncate the SHA-1 by the offset and convert it into a 32-bit
	// unsigned int. AND the 32-bit int with 0x7FFFFFFF (2147483647)
	// to get a 31-bit unsigned int.
	//   Use the offset index to truncate the SHA-1 digest to get a 32-bit unsigned integer
	//   AND the 32-bit integer with 0x7FFFFFFF (2147483647) to mask off the most significant bit and convert to an unsigned 31-bit integer
	truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

	// Take modulo 1_000_000 of the 31-bit integer to get a 6-digit TOTP code
	return truncatedHash % 1_000_000
}
