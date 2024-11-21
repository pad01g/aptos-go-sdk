package aptos

import (
	"encoding/hex"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/aptos-labs/aptos-go-sdk/internal/util"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

/**
 * Secp256k1 Specifications
 */

// Test_Spec_Secp256k1_Generation tests the generation of Secp256k1 keys.
//
//   - It must be able to generate keys.
//   - (Not covered) It should be able to generate keys with a specific seed, and have a deterministic outcome.
//   - It must not be able to generate the same key twice on default input.
func Test_Spec_Secp256k1_Generation(t *testing.T) {
	// It must be able to generate keys
	key1, err := crypto.GenerateSecp256k1Key()
	assert.NoError(t, err, "It must be able to generate keys")

	// It must be able to not generate the same key twice on default input
	key2, err := crypto.GenerateSecp256k1Key()
	assert.NoError(t, err)
	assert.NotEqual(t, key1, key2, "It must not be able to generate the same key twice on default input")
}

// Test_Spec_Secp256k1_PrivateKey tests the Secp256k1 private key
//
//   - It must be able to load a private key from a byte array
//   - It must not be able to load a private key from an invalid length byte array
//   - It must be able to load a private key from a 0x prefixed hex string
//   - It must not be able to load a private key from an invalid length hex string
//   - It must not be able to load a private key from an invalid hex string with invalid characters
//   - It must be able to load the same private key and be the same
//   - It must be able to output to a byte array
//   - It must be able to output to a 0x prefixed hex string
func Test_Spec_Secp256k1_PrivateKey(t *testing.T) {

	// It must be able to load a private key from a byte array
	key1 := &crypto.Secp256k1PrivateKey{}
	err := key1.FromBytes(parseHex(TestSecp256k1PrivateKeyHex))
	assert.NoError(t, err, "It must be able to load a private key from a byte array")

	// It must be able to load a private key from a 0x prefixed hex string
	key2 := &crypto.Secp256k1PrivateKey{}
	err = key2.FromHex(TestSecp256k1PrivateKeyHex)
	assert.NoError(t, err, "It must be able to load a private key from a 0x prefixed hex string")

	// It must not be able to load a private key from an invalid length byte array
	err = key1.FromBytes(parseHex(TestInvalidHex))
	assert.Error(t, err, "It must not be able to load a private key from an invalid length byte array")

	// It must be able to load the same private key and be the same
	assert.Equal(t, key1, key2, "It must be able to load the same private key and be the same")

	// It must not be able to load a private key from an invalid length hex string
	err = key2.FromHex(TestInvalidHex)
	assert.Error(t, err, "It must not be able to load a private key from an invalid length hex string")

	// It must not be able to load a private key from an invalid hex string with invalid characters
	err = key2.FromHex(TestInvalidHexCharacters)
	assert.Error(t, err, "It must not be able to load a private key from an invalid hex string with invalid characters")

	// It must be able to output to a byte array
	assert.Equal(t, parseHex(TestSecp256k1PrivateKeyHex), key1.Bytes(), "It must be able to output to a byte array")

	// It must be able to output to a 0x prefixed hex string
	assert.Equal(t, TestSecp256k1PrivateKeyHex, key1.ToHex(), "It must be able to output to a 0x prefixed hex string")
}

// Test_Spec_Secp256k1_PublicKey tests the Secp256k1 public key
//
//   - It must be able to load a public key from a byte array
//   - It must not be able to load a public key from an invalid length byte array
//   - It must be able to load a public key from a 0x prefixed hex string
//   - It must not be able to load a public key from an invalid length hex string
//   - It must not be able to load a private key from an invalid hex string with invalid characters
//   - It must be able to load the same public key and be the same
//   - It must be able to output to a byte array
//   - It must be able to output to a 0x prefixed hex string
//   - It must be able to encode in BCS bytes
//   - It must be able to decode from BCS bytes
//   - It must be able to encode in BCS bytes and decode back to the same
//   - It must be able to catch an invalid byte size from BCS bytes
//   - It must be able to generate an AuthenticationKey
func Test_Spec_Secp256k1_PublicKey(t *testing.T) {
	// It must be able to load a public key from a byte array
	key1 := &crypto.Secp256k1PublicKey{}
	err := key1.FromBytes(parseHex(TestSecp256k1PublicKeyHex))
	assert.NoError(t, err, "It must be able to load a public key from a byte array")

	// It must not be able to load a public key from an invalid length byte array
	err = key1.FromBytes(parseHex(TestInvalidHex))
	assert.Error(t, err, "It must not be able to load a public key from an invalid length byte array")

	// It must be able to load a public key from a 0x prefixed hex string
	key2 := &crypto.Secp256k1PublicKey{}
	err = key2.FromHex(TestSecp256k1PublicKeyHex)
	assert.NoError(t, err, "It must be able to load a public key from a 0x prefixed hex string")

	// It must not be able to load a public key from an invalid length hex string
	err = key2.FromHex(TestInvalidHex)
	assert.Error(t, err, "It must not be able to load a public key from an invalid length hex string")

	// It must not be able to load a private key from an invalid hex string with invalid characters
	err = key2.FromHex(TestInvalidHexCharacters)
	assert.Error(t, err, "It must not be able to load a public key from an invalid hex string with invalid characters")

	// It must be able to load the same public key and be the same
	assert.Equal(t, key1, key2, "It must able to load the same public key and be the same")

	// It must be able to output to a byte array
	assert.Equal(t, parseHex(TestSecp256k1PublicKeyHex), key1.Bytes(), "It must be able to output to a byte array")

	// It must be able to output to a 0x prefixed hex string
	assert.Equal(t, TestSecp256k1PublicKeyHex, key1.ToHex(), "It must be able to output to a 0x prefixed hex string")

	// It must be able to encode in BCS bytes
	bcsBytes1, err := bcs.Serialize(key1)
	assert.NoError(t, err, "It must be able to encode in BCS bytes")

	// It must be able to decode from BCS bytes
	decodedKey := &crypto.Secp256k1PublicKey{}
	err = bcs.Deserialize(decodedKey, bcsBytes1)
	assert.NoError(t, err, "It must be able to decode from BCS bytes")

	// It must be able to encode in BCS bytes and decode back to the same
	assert.Equal(t, key1, decodedKey, "It must be able to encode in BCS bytes and decode back to the same")

	// It must be able to catch an invalid byte size from BCS bytes
	err = bcs.Deserialize(decodedKey, parseHex(TestInvalidHex))
	assert.Error(t, err, "It must be able to catch an invalid byte size from BCS bytes")

	// It must be able to generate an AuthenticationKey
	// Note: This must be wrapped in a SingleSender
	anyPublicKey, err := crypto.ToAnyPublicKey(key1)
	assert.NoError(t, err, "It must be able to be wrapped in AnyPublicKey")
	authKey := anyPublicKey.AuthKey()
	assert.Equal(t, TestSecp256k1AddressHex, authKey.ToHex(), "It must be able to generate an AuthenticationKey")
}

// Test_Spec_Secp256k1_Signature tests the Secp256k1 signature
//
//   - It must be able to load a signature from a byte array
//   - It must not be able to load a signature from an invalid length byte array
//   - It must be able to load a signature from a 0x prefixed hex string
//   - It must not be able to load a signature from an invalid length hex string
//   - It must not be able to load a signature from an invalid hex string with invalid characters
//   - It must be able to load the same signature and be the same
//   - It must be able to output to a byte array
//   - It must be able to output to a 0x prefixed hex string
//   - It must be able to encode in BCS bytes
//   - It must be able to decode from BCS bytes
//   - It must be able to encode in BCS bytes and decode back to the same
//   - It must be able to catch an invalid byte size from BCS bytes
func Test_Spec_Secp256k1_Signature(t *testing.T) {
	// It must be able to load a signature from a byte array
	sig1 := &crypto.Secp256k1Signature{}
	err := sig1.FromBytes(parseHex(TestSecp256k1SignatureHex))
	assert.NoError(t, err, "It must be able to load a signature from a byte array")

	// It must not be able to load a signature from an invalid length byte array
	err = sig1.FromBytes(parseHex(TestInvalidHex))
	assert.Error(t, err, "It must not be able to load a signature from an invalid length byte array")

	// It must be able to load a signature from a 0x prefixed hex string
	sig2 := &crypto.Secp256k1Signature{}
	err = sig2.FromHex(TestSecp256k1SignatureHex)
	assert.NoError(t, err, "It must be able to load a signature from a 0x prefixed hex string")

	// It must not be able to load a signature from an invalid length hex string
	err = sig2.FromHex(TestInvalidHex)
	assert.Error(t, err, "It must not be able to load a signature from an invalid length hex string")

	// It must not be able to load a signature from an invalid hex string with invalid characters
	err = sig2.FromHex(TestInvalidHexCharacters)
	assert.Error(t, err, "It must not be able to load a signature from an invalid hex string with invalid characters")

	// It must be able to load the same signature and be the same
	assert.Equal(t, sig1, sig2, "It must able to load the same signature and be the same")

	// It must be able to output to a byte array
	assert.Equal(t, parseHex(TestSecp256k1SignatureHex), sig1.Bytes(), "It must be able to output to a byte array")

	// It must be able to output to a 0x prefixed hex string
	assert.Equal(t, TestSecp256k1SignatureHex, sig1.ToHex(), "It must be able to output to a 0x prefixed hex string")

	// It must be able to encode in BCS bytes
	bcsBytes1, err := bcs.Serialize(sig1)

	// It must be able to decode from BCS bytes
	decodedSig := &crypto.Secp256k1Signature{}
	err = bcs.Deserialize(decodedSig, bcsBytes1)
	assert.NoError(t, err, "It must be able to decode from BCS bytes")

	// It must be able to encode in BCS bytes and decode back to the same
	assert.Equal(t, sig1, decodedSig, "It must be able to encode in BCS bytes and decode back to the same")

	// It must be able to catch an invalid byte size from BCS bytes
	err = bcs.Deserialize(decodedSig, parseHex(TestInvalidHex))
	assert.Error(t, err, "It must be able to catch an invalid byte size from BCS bytes")
}

// Test_Spec_Secp256k1_Authentication tests the Secp256k1 authenticator
//
//   - It must be able to generate an AccountAuthenticator
//   - It must be able to verify the message with the AccountAuthenticator
//   - It must be able to not-verify the message with the AccountAuthenticator, with the wrong message
//   - It should be able to generate an empty signature AccountAuthenticator
//   - It must be able to encode in BCS bytes
//   - It must be able to decode from BCS bytes
//   - It must be able to encode in BCS bytes and decode back to the same
//   - It must be able to catch an invalid byte size from BCS bytes
func Test_Spec_Secp256k1_Authenticator(t *testing.T) {
	innerKey1 := &crypto.Secp256k1PrivateKey{}
	err := innerKey1.FromHex(TestSecp256k1PrivateKeyHex)
	assert.NoError(t, err)

	// Note wrap in SingleSender
	key1 := crypto.NewSingleSigner(innerKey1)
	pubKey1 := key1.PubKey()
	message := parseHex(TestSecp256k1Message)

	// It must be able to generate an AccountAuthenticator
	auth1, err := key1.Sign(message)
	assert.NoError(t, err, "It must be able to generate an AccountAuthenticator")

	// It must be able to verify the message with the AccountAuthenticator
	assert.True(t, auth1.Verify(message), "It must be able to verify the message with the AccountAuthenticator")

	// It must be able to not-verify the message with the AccountAuthenticator, with the wrong message
	message2 := parseHex(OtherMessage)
	assert.False(t, auth1.Verify(message2), "It must be able to not-verify the message with the AccountAuthenticator, with the wrong message")

	// It should be able to generate an empty signature AccountAuthenticator
	emptySig := key1.EmptySignature()
	assert.Equal(t, &crypto.AnySignature{
		Variant:   crypto.AnySignatureVariantSecp256k1,
		Signature: &crypto.Secp256k1Signature{},
	}, emptySig, "It should be able to generate an empty signature AccountAuthenticator")
	emptyAuth := key1.SimulationAuthenticator()
	assert.Equal(t, &crypto.AccountAuthenticator{
		Variant: crypto.AccountAuthenticatorSingleSender,
		Auth: &crypto.SingleKeyAuthenticator{
			PubKey: pubKey1.(*crypto.AnyPublicKey),
			Sig:    emptySig,
		},
	}, emptyAuth, "It should be able to generate an empty signature AccountAuthenticator")

	// It must be able to encode in BCS bytes
	bcsBytes1, err := bcs.Serialize(auth1)
	assert.NoError(t, err, "It must be able to encode in BCS bytes")

	// It must be able to decode from BCS bytes
	decodedAuth := &crypto.AccountAuthenticator{}
	err = bcs.Deserialize(decodedAuth, bcsBytes1)
	assert.NoError(t, err, "It must be able to decode from BCS bytes")

	// It must be able to encode in BCS bytes and decode back to the same
	assert.Equal(t, auth1, decodedAuth, "It must be able to encode in BCS bytes and decode back to the same")
}

// Test_Spec_Secp256k1_Signing tests the signing of Secp256k1 keys
//
//   - It must be able to generate a public key from the private key
//   - It must be able to sign messages
//   - It must have deterministic signing
//   - It must have different signatures for different keys
//   - It must have different signatures for different messages
//   - It must be able to verify the message with the public key
//   - It must be able to not-verify a message with the wrong public key
//   - It must be able to not-verify a message with the wrong signature

func Test_Spec_Secp256k1_Signing(t *testing.T) {
	innerKey1 := &crypto.Secp256k1PrivateKey{}
	err := innerKey1.FromHex(TestSecp256k1PrivateKeyHex)
	assert.NoError(t, err)
	key1 := crypto.NewSingleSigner(innerKey1)
	innerKey2, err := crypto.GenerateSecp256k1Key()
	assert.NoError(t, err)
	key2 := crypto.NewSingleSigner(innerKey2)

	// It must be able to generate a public key from the private key
	pubkey1 := key1.PubKey()
	pubkey2 := key2.PubKey()

	// It must be able to sign messages
	message := parseHex(TestSecp256k1Message)
	signature1, err := key1.SignMessage(message)
	assert.NoError(t, err, "It must be able to sign messages")
	// TODO: verify signature against a well known source / deal with malleability

	signature1Copy, err := key1.SignMessage(message)
	assert.NoError(t, err)
	assert.Equal(t, signature1, signature1Copy, "It must have deterministic signing")

	// It must have different signatures for different keys
	signature2, err := key2.SignMessage(message)
	assert.NoError(t, err)
	assert.NotEqual(t, signature1, signature2, "It must have different signatures for different keys")

	// It must have different signatures for different messages
	message2 := parseHex(OtherMessage)
	signature1Message2, err := key1.SignMessage(message2)
	assert.NoError(t, err)
	assert.NotEqual(t, signature1, signature1Message2, "It must have different signatures for different messages")

	// It must be able to verify the message with the public key
	assert.True(t, pubkey1.Verify(message, signature1), "It must be able to verify the message with the public key")
	assert.True(t, pubkey1.Verify(message, signature1Copy), "It must be able to verify the message with the public key")
	assert.True(t, pubkey1.Verify(message2, signature1Message2), "It must be able to verify the message with the public key")
	assert.True(t, pubkey2.Verify(message, signature2), "It must be able to verify the message with the public key")

	// It must be able to not-verify a message with the wrong public key
	assert.False(t, pubkey2.Verify(message, signature1), "It must be able to not-verify a message with the wrong public key")
	assert.False(t, pubkey1.Verify(message2, signature2), "It must be able to not-verify a message with the wrong public key")

	// It must be able to not-verify a message with the wrong signature
	assert.False(t, pubkey1.Verify(message2, signature1), "It must be able to not-verify a message with the wrong signature")
	assert.False(t, pubkey2.Verify(message2, signature2), "It must be able to not-verify a message with the wrong signature")
}

func Test_Spec_Secp256k1_Signing_2(t *testing.T) {
	signer2, err := NewSecp256k1Account()
	key2 := signer2.Signer
	address2 := signer2.AccountAddress()

	// It must be able to sign messages
	message := parseHex(TestSecp256k1Message)

	// It must have different signatures for different keys
	signature2, err := key2.SignMessage(message)

	key2Bytes := key2.PubKey().Bytes()
	t.Logf("key2Bytes hexString: %v", hex.EncodeToString(key2Bytes))
	t.Logf("key2Bytes len: %v", len(key2Bytes))

	assert.NoError(t, err)
	hexString2 := hex.EncodeToString(signature2.Bytes())
	t.Logf("signature2 hexString: %v", hexString2)
	t.Logf("signature2 len: %v", len(signature2.Bytes()))

	signature2Skipped := signature2.Bytes()[2:]

	byteArray0 := []byte{0x00}
	byteArray1 := []byte{0x01}

	sigBytes0 := append(append([]byte{}, signature2Skipped...), byteArray0...)
	sigBytes1 := append(append([]byte{}, signature2Skipped...), byteArray1...)

	t.Logf("sigBytes0 len: %v", len(sigBytes0))
	t.Logf("sigBytes0: %v", hex.EncodeToString(sigBytes0))
	t.Logf("sigBytes1 len: %v", len(sigBytes1))
	t.Logf("sigBytes1: %v", hex.EncodeToString(sigBytes1))

	t.Logf("message len: %v", len(message))
	t.Logf("message: %v", hex.EncodeToString(message))
	messageHash := util.Sha3256Hash([][]byte{message})
	t.Logf("messageHash len: %v", len(messageHash))
	t.Logf("messageHash: %v", hex.EncodeToString(messageHash))

	recovered0, err := ethCrypto.Ecrecover(messageHash, sigBytes0)
	recovered1, err := ethCrypto.Ecrecover(messageHash, sigBytes1)
	t.Logf("recovered0 len: %v", len(recovered0))
	t.Logf("recovered0: %v", hex.EncodeToString(recovered0))
	t.Logf("recovered1 len: %v", len(recovered1))
	t.Logf("recovered1: %v", hex.EncodeToString(recovered1))

	recoveredPk0 := append(append([]byte{}, []byte{0x01, 0x41}...), recovered0...)
	recoveredPk1 := append(append([]byte{}, []byte{0x01, 0x41}...), recovered1...)

	t.Logf("recoveredPk0 len: %v", len(recoveredPk0))
	t.Logf("recoveredPk0: %v", hex.EncodeToString(recoveredPk0))
	t.Logf("recoveredPk1 len: %v", len(recoveredPk1))
	t.Logf("recoveredPk1: %v", hex.EncodeToString(recoveredPk1))

	authKeyFromString0 := &crypto.AuthenticationKey{}
	authKeyFromString0.FromBytesAndScheme(recoveredPk0, crypto.SingleKeyScheme)
	accountAddress0 := AccountAddress{}
	accountAddress0.FromAuthKey(authKeyFromString0)
	aa0 := accountAddress0.String()
	t.Logf("aa0: %v", aa0)

	authKeyFromString1 := &crypto.AuthenticationKey{}
	authKeyFromString1.FromBytesAndScheme(recoveredPk1, crypto.SingleKeyScheme)
	accountAddress1 := AccountAddress{}
	accountAddress1.FromAuthKey(authKeyFromString1)
	aa1 := accountAddress1.String()
	t.Logf("aa1: %v", aa1)

	aa2 := address2.String()
	t.Logf("aa2: %v", aa2)

	t.Logf("match any: %v", aa0 == aa2 || aa1 == aa2)
}
