package oxicrypt

// Rules for errors definition
// Example OXICRPT001: Password is not set
// | Symbols | Possible values | Meaning
// | 1 - 3   | OXI             | should be always OXI to identify that the error is from OXI package
// | 4 - 7   | Package ID      | CRPT if you change this package "oxicrypt"
// | 8 - 10  | Digital number  | Number of the error
// | 11 - 14 | ": ""           | Means that error id is finished, next will be
//                             | human-readable error description
// it is possible to put whatever you like,
// I recommend to put there human-readable error description in English

// OXICRPT001encKeyIsNotSet - OXICRPT001: Password is not set, encryption/decryption is not possible
const OXICRPT001encKeyIsNotSet = "OXICRPT001: Encryption key is not created, encryption/decryption is not possible"

// OXICRPT002wrongKeyLength - OXICRPT002: key length is wrong
const OXICRPT002wrongKeyLength = "OXICRPT002: key length is wrong"

// OXICRPT003cipherNotFound - OXICRPT003: cipher is not found
const OXICRPT003cipherNotFound = "OXICRPT003: cipher is not found"

const cSaltLength = 8
