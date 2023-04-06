package oxicrypt

import "testing"

func TestNoneEncrypt(t *testing.T) {
	// As there is no encryption, check if it is the same
	var none cipherNONE
	genInitialText := generateRandomString(40, 100)
	genPass := generateRandomString(5, 32)
	err := none.SetPassword(genPass)
	if err != nil {
		t.Error(err.Error())
	}
	encrypted, err := none.Encrypt(genInitialText)
	if err != nil {
		t.Error(err.Error())
	}
	if encrypted != genInitialText {
		t.Errorf("Expected %s. retrieved %s", genInitialText, encrypted)
	}
	decrypted, err := none.Decrypt(encrypted)
	if err != nil {
		t.Error(err.Error())
	}
	if encrypted != decrypted {
		t.Errorf("Expected %s. retrieved %s", genInitialText, decrypted)
	}
}
