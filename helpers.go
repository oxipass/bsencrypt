package bsencryption

import (
	"errors"
	"math/rand"
	"unicode/utf8"
)

func formError(errorID string, errorText ...string) error {
	var finalText string
	for i, errorStr := range errorText {
		if i == 0 {
			finalText = errorStr
		} else {
			finalText = finalText + ", " + errorStr
		}
	}
	return errors.New(errorID + ": " + finalText)
}

func generateRandomString(lenFrom, lenTo int) string {
	lenMax := lenTo - lenFrom

	if lenMax <= 0 {
		return ""
	}

	const alphanum = "0123456789" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		"§±!@#$%^&*()_+=-[]{};'\\:\"|,./<>?`~" +
		"йцукенгшщзхъфывапролджэёячсмитьбю№ЙЦУКЕНГШЩЗХЪЁЭЖДЛОРПАВЫФЯЧСМИТЬБЮ"
	anLen := byte(utf8.RuneCountInString(alphanum))

	lenMax = rand.Intn(lenMax) + lenFrom

	var bytes = make([]byte, lenMax)
	rand.Read(bytes)
	finalString := ""
	for _, b := range bytes {
		finalString = finalString + string([]rune(alphanum)[b%anLen])
	}
	return finalString
}

func generateRandomBytes(lenFrom, lenTo int) []byte {
	lenMax := lenTo - lenFrom

	if lenMax <= 0 {
		return nil
	}

	lenMax = rand.Intn(lenMax) + lenFrom

	var bytes = make([]byte, lenMax)
	rand.Read(bytes)

	return bytes
}
