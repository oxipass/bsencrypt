package bsencrypt

import "testing"

const cAES256InitialText = "23nrn 2rjnc87smlk,d4of9`94384;"
const cAES256Password = "Mj577;tf,QQ"

func TestAES256EncyptDecrypt(t *testing.T) {
	var aesWrapper cipherAES256
	err := aesWrapper.SetPassword(cAES256Password)
	if err != nil {
		t.Error(err.Error())
	}
	encryptedString, err := aesWrapper.Encrypt(cAES256InitialText)
	if err != nil {
		t.Error(err.Error())
	}
	decryptedText, err := aesWrapper.Decrypt(encryptedString)
	if err != nil {
		t.Error(err.Error())
	}
	if cAES256InitialText != decryptedText {
		t.Errorf("Expected %s, retrieved %s", cAES256InitialText, decryptedText)
	}
}

func TestAES256CheckClean(t *testing.T) {
	var aesWrapper cipherAES256
	err := aesWrapper.SetPassword(cAES256Password)
	if err != nil {
		t.Error(err.Error())
	}
	encryptedString, err := aesWrapper.Encrypt(cAES256InitialText)
	if err != nil {
		t.Error(err)
	}
	decryptedText, err := aesWrapper.Decrypt(encryptedString)
	if err != nil {
		t.Error(err)
	}
	if cAES256InitialText != decryptedText {
		t.Errorf("Expected %s, retrieved %s", cAES256InitialText, decryptedText)
	}
	aesWrapper.CleanAndInit()
	decryptedText, err = aesWrapper.Decrypt(encryptedString)
	if err == nil {
		t.Error("Expected decryption error, retrieved nil")
	}
}
