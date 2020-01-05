package bsencrypt

import "testing"

const cNONEInitialText = "en47DD767d4bdjbrjhJHBHDJ"
const cNONEPassword = "drdnrd"

func TestNoneEncrypt(t *testing.T) {
	// As there is no encryption, check if it is the same
	var none cypherNONE
	err := none.SetPassword(cNONEPassword)
	if err != nil {
		t.Error(err.Error())
	}
	encrypted, err := none.Encrypt(cNONEInitialText)
	if err != nil {
		t.Error(err.Error())
	}
	if encrypted != cNONEInitialText {
		t.Errorf("Expected %s. retrieved %s", cNONEInitialText, encrypted)
	}
	decrypted, err := none.Decrypt(encrypted)
	if err != nil {
		t.Error(err.Error())
	}
	if encrypted != decrypted {
		t.Errorf("Expected %s. retrieved %s", cNONEInitialText, decrypted)
	}
}
