package totp

/*
This is an implementation that provides a call to generate a seed and OTP from a seed

Reference
TOTP: Time-Based One-Time Password Algorithm (built upon HOTP)
https://datatracker.ietf.org/doc/html/rfc6238

HOTP: An HMAC-Based One-Time Password Algorithm (Seed defined here)
https://datatracker.ietf.org/doc/html/rfc4226
*/
import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/colt3k/utils/crypt"
	"github.com/colt3k/utils/crypt/encrypt/argon2id"
	"image"
	"image/png"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Seed : creates a derived seed of 16, 26 or 32 chars; default 32
func Seed(size int) ([]byte, error) {
	if size != 16 && size != 26 && size != 32 {
		size = 32
	}
	var salt []byte
	salt = crypt.GenSalt(salt, 16)
	tkn, err := generateToken(32)
	if err != nil {
		return nil, fmt.Errorf("issue creating token %v", err)
	}
	dk, _, _ := argon2id.Key([]byte(tkn), salt, 32)
	base32Encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	dkHash := base32Encoder.EncodeToString(dk)

	return []byte(dkHash[:size]), nil
}

// GenerateQRCodeAsBase64String creates QR Barcode then converts to base64 string for display
func GenerateQRCodeAsBase64String(email, issuer string, seed []byte, width, height int) (string, error) {
	return GenerateQRCodeAsBase64StringWithTimePeriod(email, issuer, seed, 30, width, height)
}

// GenerateQRCodeAsBase64StringWithTimePeriod creates QR Barcode then converts to base64 string for display
func GenerateQRCodeAsBase64StringWithTimePeriod(email, issuer string, seed []byte, timePeriod, width, height int) (string, error) {
	i, err := GenerateQRCodeWithTimePeriod(email, issuer, seed, timePeriod, width, height)
	if err != nil {
		return "", err
	}
	var base64Encoding string
	var bytImg bytes.Buffer
	bytW := io.Writer(&bytImg)
	err = png.Encode(bytW, i)
	if err != nil {
		fmt.Printf("issue writing image to buffer: %v", err)
	} else {
		// Determine the content type of the image file
		mimeType := http.DetectContentType(bytImg.Bytes())
		// Prepend the appropriate URI scheme header depending
		// on the MIME type
		switch mimeType {
		case "image/jpeg":
			base64Encoding += "data:image/jpeg;base64,"
		case "image/png":
			base64Encoding += "data:image/png;base64,"
		}

		// Append the base64 encoded output
		base64Encoding += base64.StdEncoding.EncodeToString(bytImg.Bytes())
	}
	return base64Encoding, nil
}

/*
GenerateQRCode generates a qr code using the approved otpauth format, pass custom timePeriod or 0 for default of 30
*/
func GenerateQRCode(email, issuer string, seed []byte, width, height int) (image.Image, error) {
	return GenerateQRCodeWithTimePeriod(email, issuer, seed, 30, width, height)
}

func GenerateQRCodeWithTimePeriod(email, issuer string, seed []byte, timePeriod, width, height int) (image.Image, error) {
	if timePeriod == 0 {
		timePeriod = 30
	}
	// Generate with Value: otpauth://totp/Sprockets:jdoe@xxx.com?secret=JBSWY3DPEHPK3PXP&issuer=Sprockets
	// expanded version for specific user
	var byt bytes.Buffer
	byt.WriteString("otpauth://totp/")
	byt.WriteString(issuer)
	byt.WriteString(":")
	byt.WriteString(email)
	byt.WriteString("?secret=")
	byt.Write(seed)
	byt.WriteString("&issuer=")
	byt.WriteString(issuer)
	b, err := qr.Encode(byt.String(), qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	b, err = barcode.Scale(b, width, height)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateToken(size int) (string, error) {
	length := 26
	if size > 16 && size <= 32 {
		length = size
	}
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

/*
GenerateOTP returns OTP and time until expiration, timePeriod override, default 30sec
*/
/*
GenerateOTP returns OTP and time until expiration, timePeriod override, default 30sec
*/
func GenerateOTP(seed []byte) (string, string, string, int) {
	return GenerateOTPWithTimePeriod(seed, 30)
}

func GenerateOTPWithTimePeriod(seed []byte, timePeriod int) (string, string, string, int) {
	if timePeriod == 0 {
		timePeriod = 30
	}

	t := time.Now()
	now := t.Unix()
	// diff of seconds between now and 30 or now and next minute
	sec := t.Second()
	var exp int

	if timePeriod == 30 {
		if sec <= timePeriod {
			exp = timePeriod - sec
		} else if sec > timePeriod {
			exp = 60 - sec
		}
	} else if timePeriod == 60 {
		if sec <= timePeriod {
			exp = timePeriod - sec
		}
	}

	totpCodePrev := generateTOTP(seed, now-int64(timePeriod), timePeriod)
	totpCode := generateTOTP(seed, now, timePeriod)
	totpCodeNext := generateTOTP(seed, now+int64(timePeriod), timePeriod)
	return fmt.Sprintf("%06d", totpCodePrev), fmt.Sprintf("%06d", totpCode), fmt.Sprintf("%06d", totpCodeNext), exp
}

// Built upon the explanation and example here https://rednafi.com/go/totp_client/
func generateTOTP(secretKey []byte, timestamp int64, timePeriod int) uint32 {
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
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp)/uint64(timePeriod))

	// The timestamp bytes are concatenated with the decoded secret key
	// bytes. Then a 20-byte SHA-1 hash is calculated from the byte slice
	//   Concatenate the timestamp integer bytes with the decoded secret key bytes
	//   Hash the concatenated bytes to get a 20-byte SHA-1 digest
	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(timeBytes) // Concat the timestamp byte slice
	h := hash.Sum(nil)    // Calculate 20-byte SHA-1 digest

	// AND the SHA-1 with 0x0F (15) to get a single-digit offset
	//   Get the last byte of the SHA-1 digest and 'AND' it with 0x0F (15) to mask off all but the last 4 bits to get an offset index from 0-15
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
