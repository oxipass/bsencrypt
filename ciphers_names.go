package oxicrypt

// AES 256

const AES256Id = cCryptIDAES25601
const AES256Text = cAES256TextDescription

// No encryption

const NoneId = cNoneId
const NoneText = cNoneDescription

type CipherInfo struct {
	ID          string
	Description string
}

func GetCiphers() (ci []CipherInfo) {

	aes256 := CipherInfo{AES256Id, AES256Text}
	ci = append(ci, aes256)

	none := CipherInfo{NoneId, NoneText}
	ci = append(ci, none)
	return ci
}
