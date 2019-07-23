package bsencrypt

// No encryption consts
const cryptIDNONE = "7LD92APW"
const humanCryptNone = "NONE"

type cypherNONE struct {
	passwordKey []byte
}

func (cypher *cypherNONE) CleanAndInit() {
}

func (cypher cypherNONE) GetGryptID() string {
	return cryptIDNONE
}

func (cypher cypherNONE) GetCipherName() string {
	return humanCryptNone
}

func (cypher *cypherNONE) SetPassword(password string) error {
	return nil
}

func (cypher *cypherNONE) SetPasswordKey(passKey []byte) error {
	cypher.passwordKey = passKey
	return nil
}

func (cypher *cypherNONE) GetPasswordKey() []byte {
	return cypher.passwordKey
}

func (cypher *cypherNONE) EncryptBLOB(inStr string) ([]byte, error) {
	return []byte(inStr), nil
}

func (cypher *cypherNONE) DecryptBLOB(inData []byte) (string, error) {
	return string(inData[:]), nil
}

func (cypher *cypherNONE) EncryptBIN(inData []byte) ([]byte, error) {
	return inData, nil
}
func (cypher *cypherNONE) DecryptBIN(inData []byte) ([]byte, error) {
	return inData, nil
}

func (cypher cypherNONE) IsKeyGenerated() bool {
	return true
}

func (cypher *cypherNONE) Encrypt(text string) (string, error) {
	return text, nil
}

func (cypher *cypherNONE) Decrypt(cryptedText string) (string, error) {
	return cryptedText, nil
}
