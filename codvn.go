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
//  - https://tools.ietf.org/html/rfc2307 (Section 5.3)
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
	"unicode"
)

// Errors
var (
	ErrUnknownHash    = errors.New("unknown hash schema")
	ErrTruncatedInput = errors.New("truncated input")
	ErrDontMatch      = errors.New("password doesn't match")
)

type Kind string

func (k *Kind) Scan(state fmt.ScanState, verb rune) error {
	token, err := state.Token(true, func(c rune) bool {
		return !unicode.IsSpace(c) && !unicode.IsPunct(c)
	})
	*k = Kind(token)
	return err
}

const (
	SHA1   Kind = "sha"
	SHA256 Kind = "SHA256"
	SHA384 Kind = "SHA384"
	SHA512 Kind = "SHA512"
)

// CodvN password
type CodvN struct {
	Kind Kind
	Iter int
	Hash []byte
	Salt []byte
}

func (k Kind) newHash() (hash.Hash, error) {
	switch k {
	case SHA1:
		return sha1.New(), nil
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	}
	return nil, ErrUnknownHash
}

func (c *CodvN) UnmarshalText(text []byte) error {
	var hash string
	_, err := fmt.Sscanf(string(text), "{x-is%s,%d}%s", &c.Kind, &c.Iter, &hash)
	if err != nil {
		return err
	}
	h, err := c.Kind.newHash()
	if err != nil {
		return err
	}
	parts, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return err
	}
	size := h.Size()
	if len(parts) < size {
		return ErrTruncatedInput
	}
	c.Salt, c.Hash = parts[size:], parts[:size]
	return nil
}

func (c CodvN) String() string {
	hashed := base64.StdEncoding.EncodeToString(append(c.Hash, c.Salt...))
	return fmt.Sprintf("{x-is%s,%d}%s", c.Kind, c.Iter, hashed)
}

func (c *CodvN) MarshalText() (text []byte, err error) {
	return []byte(c.String()), nil
}

// Parse password
func Parse(text []byte) (CodvN, error) {
	var c CodvN
	err := c.UnmarshalText(text)
	return c, err
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
	h, err := c.Kind.newHash()
	if err != nil {
		return err
	}
	hash, err := Encode(h, clear, c.Salt, c.Iter)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash, c.Hash) != 1 {
		return ErrDontMatch
	}
	return nil
}

// Verify hashed password
func Verify(hashed, clear []byte) error {
	var c CodvN
	if err := c.UnmarshalText(hashed); err != nil {
		return err
	}
	return c.Verify(clear)
}
