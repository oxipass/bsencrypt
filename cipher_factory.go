package oxicrypt

import "errors"

// Add your cipher implementations in factory below

// GetOxiCipher - ciphers factory, get the object here
func GetOxiCipher(cipherId string) (OxiCipher, error) {
	switch cipherId {
	case cCryptIDAES25601:
		return new(cipherAES256), nil
	case cNoneId:
		return new(cipherNONE), nil
	default:
		return nil, errors.New(OXICRPT003cipherNotFound)
	}
}
