package oxicrypt

import (
	"math/rand"
	"testing"
	"time"
	"unicode/utf8"
)

func TestRandomStringGenerator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	lenFrom := rand.Intn(50)
	lenTo := lenFrom + rand.Intn(200) + 1

	randStr := generateRandomString(lenFrom, lenTo)

	lenStr := utf8.RuneCountInString(randStr)
	if lenStr >= lenFrom && lenStr <= lenTo {
		t.Logf("Correctly generated, lenFrom = %d, lenTo = %d, actual len: %d, generated string: '%s'", lenFrom, lenTo, lenStr, randStr)
	} else {
		t.Errorf("Expected the length from %d to %d but get %d, generated string: '%s' ", lenFrom, lenTo, len(randStr), randStr)
	}
}

func TestSaltGenerator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	salt := generateSalt()
	if len(salt) != cSaltLength {
		t.Errorf("wrong salt length")
	}
	salt2 := generateSalt()
	if salt == salt2 {
		t.Errorf("duplication of the salt")
	}
}

func TestRandomStringGeneratorWrongInput(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	lenTo := rand.Intn(50)
	lenFrom := lenTo + rand.Intn(200)

	randStr := generateRandomString(lenFrom, lenTo)
	if len(randStr) > 0 {
		t.Errorf("Expected empty string because lenFrom(%d) is more or equal lenTo(%d) but received '%s'", lenFrom, lenTo, randStr)
	}
}

func TestFormError(t *testing.T) {
	e := formError("BSENCRPT0001", "Error 1", "Error 2")
	if e == nil {
		t.Errorf("Error returns nil instead actual value")
	} else if e.Error() != "BSENCRPT0001: Error 1, Error 2" {
		t.Errorf("Error is not formed as expected")
	}
}

func TestRandomBytesGenerator(t *testing.T) {
	genBytes := generateRandomBytesWithRandomLen(4, 10)
	genLen := len(genBytes)
	if genLen < 4 || genLen > 10 {
		t.Errorf("Wrong length array is generated")
	}
}

func TestRandomBytesGeneratorFailure(t *testing.T) {
	genBytes := generateRandomBytesWithRandomLen(5, 4)
	if genBytes != nil {
		t.Errorf("Wrong parameters not processed correctly, max is less than min but array is generated")
	}
}

func TestCypherNamesAndIDs(t *testing.T) {
	for _, cipher := range GetCiphers() {
		if len(cipher.ID) == 0 {
			t.Errorf("Crypt ID cannot be empty, its length should be 8 symbols")
		} else if len(cipher.ID) != 8 {
			t.Errorf("Wrong length of crypt ID, should be 8, CryptID: %s", cipher.ID)
		}
		if len(cipher.Description) == 0 {
			t.Errorf("Human readable cipher name is empty, should be at least 3 symbols")
		} else if len(cipher.Description) < 3 {
			t.Errorf("Human readable cipher name should be at least 3 symbols")
		}

	}
}

func TestEmptyPassword(t *testing.T) {

}

func TestShortPassword(t *testing.T) {

}

func TestNormalPassword(t *testing.T) {

}

func TestEmptyEncryptionSource(t *testing.T) {
}

// TestShortEncryptionData - encrypt/decrypt the strings with the length from 1 to 10
func TestShortEncryptionString(t *testing.T) {
	EncryptionCheckHelper(t, 1, 10)
}

func EncryptionCheckHelper(t *testing.T, minLen int, maxLen int) {
	for _, cipherInfo := range GetCiphers() {
		cipher, errCipher := GetOxiCipher(cipherInfo.ID)
		if errCipher != nil {
			t.Error(errCipher.Error())
			continue
		}
		cipher.CleanAndInit()
		password := generateRandomString(1, 20)
		plainText := generateRandomString(minLen, maxLen)
		err := cipher.SetPassword(password)
		if err != nil {
			t.Errorf("Cipher: %s, SetPassword (%s) error: %s",
				cipher.GetCipherName(), password, err.Error())
			continue
		}
		encryptedText, err := cipher.Encrypt(plainText)
		if err != nil {
			t.Errorf("Cipher: %s, Encryption error: %s, password: '%s', text2encypt: '%s'",
				cipher.GetCipherName(), err.Error(), password, plainText)
			continue
		}
		cipher.CleanAndInit()
		err = cipher.SetPassword(password)
		if err != nil {
			t.Errorf("Cipher: %s, SetPassword (%s) error: %s",
				cipher.GetCipherName(), password, err.Error())
			continue
		}
		decryptedText, err := cipher.Decrypt(encryptedText)
		if err != nil {
			t.Errorf("Cipher: %s, Decryption error: %s, password: '%s', text2encypt: '%s', text2decrypt: '%s'",
				cipher.GetCipherName(), err.Error(), password, plainText, encryptedText)
			continue
		}
		if plainText != decryptedText {
			t.Errorf("Cipher: %s, Decryption error: source and result are not equal, password: '%s', text2encypt: '%s', decryptedText: '%s' ",
				cipher.GetCipherName(), password, plainText, decryptedText)
		}
	}
}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 10 to 100
func TestMediumEncryptionStrings(t *testing.T) {
	EncryptionCheckHelper(t, 10, 100)
}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 100 to 1000
func TestBigEncryptionString(t *testing.T) {
	EncryptionCheckHelper(t, 100, 1000)
}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 1000 to 60000
func TestHugeEncryptionString(t *testing.T) {
	EncryptionCheckHelper(t, 1000, 60000)
}

// TestShortEncryptionData - encrypt/decrypt the data with the length from 1 to 100
func TestShortEncryptionData(t *testing.T) {
}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 100 to 1000
func TestMediumEncryptionData(t *testing.T) {

}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 1000 to 50000
func TestBigEncryptionData(t *testing.T) {

}

// TestMediumEncryptionData - encrypt/decrypt the strings with the length from 50000 to 1000000
func TestHugeEncryptionData(t *testing.T) {

}
