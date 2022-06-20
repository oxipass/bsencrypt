package oxicrypt

import "testing"

func TestAES256EncryptDecrypt(t *testing.T) {
	var aesWrapper cipherAES256
	genInitialText := generateRandomString(40, 100)
	genPass := generateRandomString(5, 32)
	err := aesWrapper.SetPassword(genPass)
	if err != nil {
		t.Error(err.Error())
	}
	encryptedString, err := aesWrapper.Encrypt(genInitialText)
	if err != nil {
		t.Error(err.Error())
	}
	decryptedText, err := aesWrapper.Decrypt(encryptedString)
	if err != nil {
		t.Error(err.Error())
	}
	if genInitialText != decryptedText {
		t.Errorf("Expected %s, retrieved %s", genInitialText, decryptedText)
	}
}

func TestAES256CheckClean(t *testing.T) {
	var aesWrapper cipherAES256
	genInitialText := generateRandomString(40, 100)
	genPass := generateRandomString(5, 32)
	err := aesWrapper.SetPassword(genPass)
	if err != nil {
		t.Error(err.Error())
	}
	encryptedString, err := aesWrapper.Encrypt(genInitialText)
	if err != nil {
		t.Error(err)
	}
	decryptedText, err := aesWrapper.Decrypt(encryptedString)
	if err != nil {
		t.Error(err)
	}
	if genInitialText != decryptedText {
		t.Errorf("Expected %s, retrieved %s", genInitialText, decryptedText)
	}
	aesWrapper.CleanAndInit()
	_, err = aesWrapper.Decrypt(encryptedString)
	if err == nil {
		t.Error("Expected decryption error, retrieved nil")
	}
}
