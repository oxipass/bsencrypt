package oxicrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// AES256 constants
const cCryptIDAES25601 = "8GA63DMN"
const cAES256TextDescription = "AES256V1"
const cAESKeyLength = 32 // AES-256
const cPassSalt = "DJLiw3;!"
const cLoops = 32768 // Increase it with computer power

type cipherAES256 struct {
	passwordKey    []byte
	cachedFinalKey []byte
}

func (cipher256 *cipherAES256) CleanAndInit() {
	cipher256.passwordKey = nil
	cipher256.cachedFinalKey = nil
}

func (cipher256 cipherAES256) GetCryptID() string {
	return cCryptIDAES25601
}

func (cipher256 cipherAES256) GetCipherName() string {
	return cAES256TextDescription
}
func (cipher256 *cipherAES256) SetPassword(password string) (err error) {

	cipher256.passwordKey = cipher256.makePasswordKey(password)
	err = cipher256.SetPasswordKey(cipher256.passwordKey)
	if err != nil {
		return err
	}
	return nil
}

func (cipher256 cipherAES256) makePasswordKey(password string) (keyDataOut []byte) {
	passWithSalt := password + cPassSalt
	for len(passWithSalt) < cAESKeyLength {
		passWithSalt += passWithSalt
	}
	return []byte(passWithSalt)
}

func (cipher256 cipherAES256) GetPasswordKey() []byte {
	return cipher256.passwordKey
}

func (cipher256 *cipherAES256) SetPasswordKey(keyDataIn []byte) (err error) {
	if len(keyDataIn) < cAESKeyLength {
		return formError(BSENCRPT0002WrongKeyLength, cAES256TextDescription, "SetPasswordKey", "Key length must be  at least 32 bytes")
	}
	cipher256.passwordKey = keyDataIn
	return nil
}

func (cipher256 cipherAES256) IsPasswordSet() bool {
	if cipher256.passwordKey == nil {
		return false
	}
	return true
}

func (cipher256 *cipherAES256) Encrypt(text string) (string, error) {
	encryptedData, err := cipher256.EncryptBLOB(text)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encryptedData), nil
}

func (cipher256 *cipherAES256) EncryptBLOB(text string) ([]byte, error) {
	plainData := []byte(text)
	encryptedData, err := cipher256.EncryptBIN(plainData)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

func (cipher256 *cipherAES256) EncryptBIN(inData []byte) (outData []byte, err error) {
	if cipher256.IsPasswordSet() == false {
		return nil, formError(BSENCRPT0001EncKeyIsNotSet)
	}

	if cipher256.cachedFinalKey == nil {
		cipher256.cachedFinalKey, err = scrypt.Key(cipher256.passwordKey, nil, cLoops, 8, 1, cAESKeyLength)
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(cipher256.cachedFinalKey)
	if err != nil {
		cipher256.cachedFinalKey = nil // Clear cache in case of failure
		return nil, formError("aes.NewCipher", err.Error())
	}
	encryptedData := make([]byte, aes.BlockSize+len(inData))
	iv := encryptedData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		cipher256.cachedFinalKey = nil // Clear cache in case of failure
		return nil, formError("ReadFull", err.Error())
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedData[aes.BlockSize:], inData)

	return encryptedData, nil
}

func (cipher256 *cipherAES256) Decrypt(encryptedText string) (string, error) {
	dataIn, err := base64.URLEncoding.DecodeString(encryptedText)

	if err != nil {
		return "", err
	}

	decryptedText, err := cipher256.DecryptBLOB(dataIn)
	if err != nil {
		return "", err
	}

	return decryptedText, nil
}

func (cipher256 *cipherAES256) DecryptBLOB(dataIn []byte) (string, error) {

	dataOut, err := cipher256.DecryptBIN(dataIn)
	if err != nil {
		return "", err
	}
	return string(dataOut), nil
}

func (cipher256 *cipherAES256) DecryptBIN(dataIn []byte) (dataOut []byte, err error) {
	if cipher256.IsPasswordSet() == false {
		return nil, formError(BSENCRPT0001EncKeyIsNotSet, cAES256TextDescription, "DecryptBIN")
	}
	if cipher256.cachedFinalKey == nil {
		cipher256.cachedFinalKey, err = scrypt.Key(cipher256.passwordKey, nil, cLoops, 8, 1, cAESKeyLength)
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(cipher256.cachedFinalKey)

	if err != nil {
		cipher256.cachedFinalKey = nil // Clear cache in case of failure
		return nil, err
	}

	if len(dataIn) < aes.BlockSize {
		cipher256.cachedFinalKey = nil // Clear cache in case of failure
		return nil, errors.New("Cipher text is too short for AES")
	}

	iv := dataIn[:aes.BlockSize]
	dataWork := dataIn[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(dataWork, dataWork)

	return dataWork, nil
}
