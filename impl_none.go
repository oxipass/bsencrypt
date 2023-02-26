package oxicrypt

const cNoneId = "7LD92APW"
const cNoneDescription = "NONE"

type cipherNONE struct {
	passwordKey []byte
}

func (cipher *cipherNONE) CleanAndInit() {
}

func (cipher *cipherNONE) GetCryptID() string {
	return cNoneId
}

func (cipher *cipherNONE) GetCipherName() string {
	return cNoneDescription
}

func (cipher *cipherNONE) SetPassword(_ string) error {
	return nil
}

func (cipher *cipherNONE) SetPasswordKey(passKey []byte) error {
	cipher.passwordKey = passKey
	return nil
}
func (cipher *cipherNONE) IsPasswordSet() bool {
	return true
}

func (cipher *cipherNONE) GetPasswordKey() []byte {
	return cipher.passwordKey
}

func (cipher *cipherNONE) EncryptBLOB(inStr string) ([]byte, error) {
	return []byte(inStr), nil
}

func (cipher *cipherNONE) DecryptBLOB(inData []byte) (string, error) {
	return string(inData[:]), nil
}

func (cipher *cipherNONE) EncryptBIN(inData []byte) ([]byte, error) {
	return inData, nil
}
func (cipher *cipherNONE) DecryptBIN(inData []byte) ([]byte, error) {
	return inData, nil
}

func (cipher *cipherNONE) Encrypt(text string) (string, error) {
	return text, nil
}

func (cipher *cipherNONE) Decrypt(encryptedText string) (string, error) {
	return encryptedText, nil
}
