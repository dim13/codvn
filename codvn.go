// Package codvn implements SAP CODVN H password hashing algorithm (PWDSALTEDHASH)
//
// Format example:
//   {x-issha, 1024}base64(hash(20 bytes) . salt(12 bytes))
//
// Where:
//   {x-issha, 1024}     encoding=RFC2307, algorithm=iSSHA-1,   iterations=1024,  saltsize=96
//   {x-isSHA256, 10000} encoding=RFC2307, algorithm=iSSHA-256, iterations=10000, saltsize=128
//   {x-isSHA384, 7500}  encoding=RFC2307, algorithm=iSSHA-384, iterations=7500,  saltsize=96
//   {x-isSHA512, 15000} encoding=RFC2307, algorithm=iSSHA-512, iterations=15000, saltsize=128
//
// References:
//  - RFC2307
//  - https://www.onapsis.com/blog/understanding-sap-codvn-h-algorithm
//  - https://hashcat.net/wiki/doku.php?id=example_hashes
//  - https://hashcat.net/forum/thread-3804.html
//
package codvn

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strconv"
)

// Errors
var (
	ErrUnknownHash    = errors.New("unknown hash schema")
	ErrTruncatedInput = errors.New("truncated input")
	ErrDontMatch      = errors.New("password doesn't match")
)

// CodvN password
type CodvN struct {
	h    hash.Hash
	kind string
	iter int
	hash []byte
	salt []byte
}

func (c CodvN) String() string {
	hashed := base64.StdEncoding.EncodeToString(append(c.hash, c.salt...))
	return fmt.Sprintf("{x-is%s, %d}%s", c.kind, c.iter, hashed)
}

// Parse password
func Parse(raw []byte) (CodvN, error) {
	var c CodvN
	re := regexp.MustCompile(`^{x-is([[:alnum:]]+), *([[:digit:]]+)}(.*)$`)
	match := re.FindStringSubmatch(string(raw))
	if len(match) != 4 {
		return c, ErrUnknownHash
	}
	switch match[1] {
	case "sha":
		c.h = sha1.New()
	case "SHA256":
		c.h = sha256.New()
	case "SHA384":
		c.h = sha512.New384()
	case "SHA512":
		c.h = sha512.New()
	default:
		return c, ErrUnknownHash
	}
	c.kind = match[1]
	iter, err := strconv.Atoi(match[2])
	if err != nil {
		return c, err
	}
	c.iter = iter
	parts, err := base64.StdEncoding.DecodeString(match[3])
	if err != nil {
		return c, err
	}
	size := c.h.Size()
	if len(parts) < size {
		return c, ErrTruncatedInput
	}
	c.hash = parts[:size]
	c.salt = parts[size:]
	return c, nil
}

// Encode password
func Encode(h hash.Hash, pass, salt []byte, iter int) ([]byte, error) {
	for i := 0; i < iter; i++ {
		h.Reset()
		h.Write(pass)
		h.Write(salt)
		salt = h.Sum(nil)
	}
	return salt, nil
}

// Verify hashed password
func (c CodvN) Verify(clear []byte) error {
	hash, err := Encode(c.h, clear, c.salt, c.iter)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash, c.hash) != 1 {
		return ErrDontMatch
	}
	return nil
}

// Verify hashed password
func Verify(hashed, clear []byte) error {
	c, err := Parse(hashed)
	if err != nil {
		return err
	}
	return c.Verify(clear)
}
