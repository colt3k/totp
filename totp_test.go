package totp

import (
	"testing"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestSeed(t *testing.T) {
	for i := 0; i < 2; i++ {
		s, err := Seed(32)
		if err != nil {
			t.Fail()
		}
		t.Logf("Seed %v", string(s))
		otpPrev, otp, otpNext, exp := GenerateOTP(s)

		t.Logf("   OTP (prev,cur,next) %v\t%v\t%v ; expiration in %v secs", otpPrev, otp, otpNext, exp)
	}
}

func TestOTP(t *testing.T) {
	otpPrev, otp, otpNext, exp := GenerateOTP([]byte("I2L337PGAURUVO6DJDNEXF2ZKTXP5VOY"))
	t.Logf("   OTP (prev,cur,next) %v\t%v\t%v ; expiration in %v secs", otpPrev, otp, otpNext, exp)
}