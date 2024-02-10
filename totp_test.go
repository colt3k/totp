package totp

import (
	"bytes"
	iout "github.com/colt3k/utils/io"
	"github.com/colt3k/utils/osut"
	"image/png"
	"io"
	"testing"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestSeed(t *testing.T) {
	for i := 0; i < 2; i++ {
		s, err := Seed(32)
		if err != nil {
			t.Logf("failed to generate seed %v", err)
			t.Fail()
		}
		t.Logf("Seed %v", string(s))
		_, err = GenerateQRCodeAsBase64String("jdoe@xxx.com", "Sprockets", s, 200, 200)
		if err != nil {
			t.Logf("failed to generate barcode %v", err)
			t.Fail()
		}
		otpPrev, otp, otpNext, exp := GenerateOTP(s)

		t.Logf("   OTP (prev,cur,next) %v\t%v\t%v ; expiration in %v secs", otpPrev, otp, otpNext, exp)
	}
}

func TestOTP(t *testing.T) {
	otpPrev, otp, otpNext, exp := GenerateOTP([]byte("D2YZUNMIUD43GE4K7EADYFCYPY"))
	t.Logf("   OTP (prev,cur,next) %v\t%v\t%v ; expiration in %v secs", otpPrev, otp, otpNext, exp)
	otpPrev, otp, otpNext, exp = GenerateOTPWithTimePeriod([]byte("D2YZUNMIUD43GE4K7EADYFCYPY"), 60)
	t.Logf("   OTP (prev,cur,next) %v\t%v\t%v ; expiration in %v secs", otpPrev, otp, otpNext, exp)
}

func TestGenerateQRCode(t *testing.T) {
	i, err := GenerateQRCode("jdoe@xxx.com", "Sprockets", []byte("I2L337PGAURUVO6DJDNEXF2ZKTXP5VOY"), 200, 200)
	if err != nil {
		t.Logf("failed to generate qr %v", err)
		t.Fail()
	}

	var bytImg bytes.Buffer
	bytW := io.Writer(&bytImg)
	err = png.Encode(bytW, i)
	if err != nil {
		t.Logf("issue writing image to buffer: %v", err)
		t.Fail()
	}

	_, err = iout.WriteOut(bytImg.Bytes(), "test.png")
	if err != nil {
		t.Logf("issue writing out image: %v", err)
		t.Fail()
	}
	s, err := osut.CallCmd("qrencode -t ansiutf8 < ./test.png")
	if err != nil {
		t.Logf("issue calling qrencode: %v", err)
		t.Fail()
	}
	t.Logf("   OTP (QR Code completed) %s", s)
}

func TestGenerateQRCodeWithTimePeriod(t *testing.T) {
	i, err := GenerateQRCodeWithTimePeriod("jdoe@xxx.com", "Sprockets", []byte("I2L337PGAURUVO6DJDNEXF2ZKTXP5VOY"), 60, 200, 200)
	if err != nil {
		t.Logf("failed to generate qr %v", err)
		t.Fail()
	}

	var bytImg bytes.Buffer
	bytW := io.Writer(&bytImg)
	err = png.Encode(bytW, i)
	if err != nil {
		t.Logf("issue writing image to buffer: %v", err)
		t.Fail()
	}

	_, err = iout.WriteOut(bytImg.Bytes(), "test.png")
	if err != nil {
		t.Logf("issue writing out image: %v", err)
		t.Fail()
	}
	s, err := osut.CallCmd("qrencode -t ansiutf8 < ./test.png")
	if err != nil {
		t.Logf("issue calling qrencode: %v", err)
		t.Fail()
	}
	t.Logf("   OTP (QR Code completed) %s", s)
}
