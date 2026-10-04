package auth

import (
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// RFC 6238 parameters shared with common authenticator apps.
// Skew is clock tolerance, not the account lockout threshold.
const (
	totpPeriod = 30
	totpSkew   = 1
)

func newTOTPSecret(account string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Stile",
		AccountName: account,
		Period:      totpPeriod,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func validateCode(secret, code string, now time.Time) bool {
	if secret == "" || code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

func otpauthURI(account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", "Stile")
	v.Set("period", "30")
	v.Set("digits", "6")
	v.Set("algorithm", "SHA1")
	return "otpauth://totp/" + url.PathEscape("Stile:"+account) + "?" + v.Encode()
}
