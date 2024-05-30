package crypto

import "github.com/aptos-labs/aptos-go-sdk/bcs"

// Signer a generic interface for any kind of signing
type Signer interface {
	// ToHex if a private key, it's bytes, if it's not a private key
	// then a placeholder
	ToHex

	// Sign signs a transaction and returns an associated authenticator
	Sign(msg []byte) (authenticator *Authenticator, err error)

	// AuthKey gives the AuthenticationKey associated with the signer
	AuthKey() *AuthenticationKey
}

// PrivateKey a generic interface for a signing private key
// This is not serializable, because this doesn't go on-chain
type PrivateKey interface {
	Signer
	CryptoMaterial

	// PubKey Retrieve the public key for signature verification
	PubKey() PublicKey
}

// PublicKey a generic interface for a public key associated with the private key
type PublicKey interface {
	bcs.Struct
	CryptoMaterial
	ToHex
	FromHex
	ToBytes
	FromBytes

	// Scheme The scheme used for address derivation
	Scheme() uint8

	// Verify verifies a message with the public key
	Verify(msg []byte, sig Signature) bool
}

type Signature interface {
	bcs.Struct
	CryptoMaterial
	ToHex
	FromHex
	ToBytes
	FromBytes
}

type CryptoMaterial interface {
	ToHex
	FromHex
	ToBytes
	FromBytes
}

type FromHex interface {
	// FromHex loads the key from the hex string
	FromHex(string) error
}

type ToHex interface {
	ToHex() string
}

type FromBytes interface {
	// FromBytes loads the key from bytes
	FromBytes([]byte) error
}

type ToBytes interface {
	// CryptoMaterial loads the key from bytes
	Bytes() []byte
}
