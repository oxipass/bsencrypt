package oxicrypt

import (
	"errors"
	"log"
	"math/rand"
	"strings"
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

const cAlphaNum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+=-[]{};:|,./<>?~"

const cMaxLen = len(cAlphaNum)

func generateRandomString(lenFrom, lenTo int) string {
	lenMax := lenTo - lenFrom
	if lenMax <= 0 {
		return ""
	}

	lenMax = rand.Intn(lenMax) + lenFrom
	log.Printf("LenMax: %d", lenMax)
	i := 0
	var builder strings.Builder

	for i < lenMax {
		randI := rand.Intn(cMaxLen)
		symbol := cAlphaNum[randI]
		_, err := builder.WriteString(string(symbol))
		if err != nil {
			log.Println(err)
			return builder.String()
		}
		i++
	}
	return builder.String()
}

func generateSalt() string {
	var builder strings.Builder
	i := 0

	for i < cSaltLength {
		randI := rand.Intn(cMaxLen)
		symbol := cAlphaNum[randI]
		_, err := builder.WriteString(string(symbol))
		if err != nil {
			log.Println(err)
			return builder.String()
		}
		i++
	}
	return builder.String()
}

func generateRandomBytesWithRandomLen(lenFrom, lenTo int) []byte {
	lenMax := lenTo - lenFrom

	if lenMax <= 0 {
		return nil
	}

	lenMax = rand.Intn(lenMax) + lenFrom

	var bytes = make([]byte, lenMax)
	rand.Read(bytes)

	return bytes
}
