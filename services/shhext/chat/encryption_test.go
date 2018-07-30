package chat

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

var cleartext = []byte("hello")

func TestEncryptionServiceTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptionServiceTestSuite))
}

type EncryptionServiceTestSuite struct {
	suite.Suite
	alicedb *leveldb.DB
	bobdb   *leveldb.DB
	alice   *EncryptionService
	bob     *EncryptionService
}

func (s *EncryptionServiceTestSuite) SetupTest() {
	alicedb, err := leveldb.Open(storage.NewMemStorage(), nil)

	if err != nil {
		panic(err)
	}
	bobdb, err := leveldb.Open(storage.NewMemStorage(), nil)

	if err != nil {
		panic(err)
	}

	s.alicedb = alicedb
	s.bobdb = bobdb
	s.alice = NewEncryptionService(NewPersistenceService(alicedb))
	s.bob = NewEncryptionService(NewPersistenceService(bobdb))
}

func (s *EncryptionServiceTestSuite) TearDownTest() {
	s.NoError(s.alicedb.Close())
	s.NoError(s.bobdb.Close())
}

// Alice sends Bob an encrypted message with DH using an ephemeral key
// and Bob's identity key.
// Bob is able to decrypt it.
// Alice does not re-use the symmetric key
func (s *EncryptionServiceTestSuite) TestEncryptPayloadNoBundle() {
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	encryptionResponse1, err := s.alice.EncryptPayload(&bobKey.PublicKey, aliceKey, cleartext)
	s.NoError(err)

	cyphertext1 := encryptionResponse1.EncryptedPayload
	ephemeralKey1 := encryptionResponse1.EphemeralKey

	s.NotNil(ephemeralKey1, "It generates an ephemeral key for DH exchange")
	s.NotNil(cyphertext1, "It generates an encrypted payload")
	s.NotEqualf(cyphertext1, cleartext, "It encrypts the payload correctly")
	s.Equalf(encryptionResponse1.EncryptionType, EncryptionTypeDH, "It sets the encryption type to DH")

	// On the receiver side, we should be able to decrypt using our private key and the ephemeral just sent
	decryptedPayload1, err := s.bob.DecryptWithDH(bobKey, ephemeralKey1, cyphertext1)
	s.NoError(err)
	s.Equalf(cleartext, decryptedPayload1, "It correctly decrypts the payload using DH")

	// The next message will not be re-using the same key
	encryptionResponse2, err := s.alice.EncryptPayload(&bobKey.PublicKey, aliceKey, cleartext)
	s.NoError(err)

	cyphertext2 := encryptionResponse2.EncryptedPayload
	ephemeralKey2 := encryptionResponse2.EphemeralKey

	s.NotEqual(cyphertext1, cyphertext2, "It does not re-use the symmetric key")
	s.NotEqual(ephemeralKey1, ephemeralKey2, "It does not re-use the ephemeral key")
	s.Equalf(EncryptionTypeDH, encryptionResponse2.EncryptionType, "It sets the encryption type to DH")

	decryptedPayload2, err := s.bob.DecryptWithDH(bobKey, ephemeralKey2, cyphertext2)
	s.NoError(err)

	s.Equalf(cleartext, decryptedPayload2, "It correctly decrypts the payload using DH")
}

// Alice has Bob's bundle
// Alice sends Bob an encrypted message with X3DH using an ephemeral key
// and Bob's bundle.
func (s *EncryptionServiceTestSuite) TestEncryptPayloadBundle() {
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	// Create a couple of bundles
	bobBundle1, err := s.bob.CreateBundle(bobKey)
	s.NoError(err)
	bobBundle2, err := s.bob.CreateBundle(bobKey)
	s.NoError(err)

	s.NotEqualf(bobBundle1, bobBundle2, "It creates different bundles")

	// We add bob bundle
	err = s.alice.ProcessPublicBundle(bobBundle2)
	s.NoError(err)

	// We send a message using the bundle
	encryptionResponse1, err := s.alice.EncryptPayload(&bobKey.PublicKey, aliceKey, cleartext)
	s.NoError(err)

	cyphertext1 := encryptionResponse1.EncryptedPayload
	ephemeralKey1 := encryptionResponse1.EphemeralKey

	s.NoError(err)
	s.NotNil(cyphertext1, "It generates an encrypted payload")
	s.NotEqualf(cyphertext1, cleartext, "It encrypts the payload correctly")
	s.NotNil(ephemeralKey1, "It generates an ephemeral key")
	s.Equalf(encryptionResponse1.EncryptionType, EncryptionTypeX3DH, "It sets the encryption type to X3DH")

	// Bob is able to decrypt it using the bundle
	bundleID := bobBundle2.GetSignedPreKey()

	s.Equalf(encryptionResponse1.BundleID, bundleID, "It sets the bundle id")

	decryptedPayload1, err := s.bob.DecryptWithX3DH(bobKey, &aliceKey.PublicKey, ephemeralKey1, bundleID, cyphertext1)
	s.NoError(err)
	s.Equalf(cleartext, decryptedPayload1, "It correctly decrypts the payload using X3DH")

	// Alice sends another message, this time she will use the same key as generated previously
	encryptionResponse2, err := s.alice.EncryptPayload(&bobKey.PublicKey, aliceKey, cleartext)
	s.NoError(err)

	cyphertext2 := encryptionResponse2.EncryptedPayload
	ephemeralKey2 := encryptionResponse2.EphemeralKey

	s.NoError(err)
	s.NotNil(cyphertext2, "It generates an encrypted payload")
	s.NotEqualf(cyphertext2, cleartext, "It encrypts the payload correctly")
	s.Equal(ephemeralKey1, ephemeralKey2, "It returns the same ephemeral key")

	// Bob this time should be able to decrypt it with a symmetric key
	decryptedPayload2, err := s.bob.DecryptSymmetricPayload(&aliceKey.PublicKey, ephemeralKey2, cyphertext2)
	s.NoError(err)
	s.Equalf(cleartext, decryptedPayload2, "It correctly decrypts the payload using a symmetric key")
}
