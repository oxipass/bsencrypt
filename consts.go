package bsencryption

// Rules for errors definition
// Example BSENCRPT00001: Password is not set
// | Symbols | Possible values | Meaning
// | 1 - 2   | BS              | should be always BS to identify that the error is from BykovStorage
// | 3 - 8   | Package ID      | ENCRPT if you change this package "bsencryption"
// | 9 - 12  | Digital number  | Number of the error
// | 13 - 14 | ": ""           | Means that error id is finished, next will be desription
// it is possible to put whatewer you like, I recommend to put there human readable error description in English

// BSENCRPT0001EncKeyIsNotSet - BSENCRPT0001: Password is not set, encryption/decryption is not possible
const BSENCRPT0001EncKeyIsNotSet = "BSENCRPT0001: Encryption key is not created, encryption/decryption is not possible"

//BSENCRPT0002WrongKeyLength - BSENCRPT0002: key length is wrong
const BSENCRPT0002WrongKeyLength = "BSENCRPT0002: key length is wrong"
