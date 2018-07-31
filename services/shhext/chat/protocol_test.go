package chat

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/suite"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

func TestProtocolServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ProtocolServiceTestSuite))
}

type ProtocolServiceTestSuite struct {
	suite.Suite
	alicedb *leveldb.DB
	bobdb   *leveldb.DB
	alice   *ProtocolService
	bob     *ProtocolService
}

func (s *ProtocolServiceTestSuite) SetupTest() {
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
	s.alice = NewProtocolService(NewEncryptionService(NewPersistenceService(alicedb)))
	s.bob = NewProtocolService(NewEncryptionService(NewPersistenceService(bobdb)))
}

func (s *ProtocolServiceTestSuite) TearDownTest() {
	s.NoError(s.alicedb.Close())
	s.NoError(s.bobdb.Close())
}

func (s *ProtocolServiceTestSuite) TestBuildDirectMessage() {
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	payload, err := proto.Marshal(&OneToOnePayload{
		Content:     "Test content",
		ClockValue:  1,
		ContentType: "a",
		MessageType: "some type",
	})
	s.NoError(err)

	marshaledMsg, err := s.alice.BuildDirectMessage(aliceKey, &bobKey.PublicKey, payload)

	s.NoError(err)
	s.NotNilf(marshaledMsg, "It creates a message")

	unmarshaledMsg := &ProtocolMessage{}
	err = proto.Unmarshal(marshaledMsg, unmarshaledMsg)

	s.NoError(err)

	s.NotNilf(unmarshaledMsg.GetBundle(), "It adds a bundle to the message")

	directMessage := unmarshaledMsg.GetDirectMessage()

	s.NotNilf(directMessage, "It sets the direct message")

	encryptedPayload := directMessage.GetPayload()

	s.NotNilf(encryptedPayload, "It sets the payload of the message")

	s.NotEqualf(payload, encryptedPayload, "It encrypts the payload")
}

func (s *ProtocolServiceTestSuite) TestBuildAndReadDirectMessage() {
	bobKey, err := crypto.GenerateKey()
	s.NoError(err)
	aliceKey, err := crypto.GenerateKey()
	s.NoError(err)

	payload := OneToOnePayload{
		Content:     "Test content",
		ClockValue:  1,
		ContentType: "a",
		MessageType: "some type",
	}

	marshaledPayload, err := proto.Marshal(&payload)
	s.NoError(err)

	// Message is sent with DH
	marshaledMsg, err := s.alice.BuildDirectMessage(aliceKey, &bobKey.PublicKey, marshaledPayload)

	s.NoError(err)

	// Bob is able to decrypt the message
	unmarshaledMsg, err := s.bob.HandleMessage(bobKey, &aliceKey.PublicKey, marshaledMsg)
	s.NoError(err)

	s.NotNil(unmarshaledMsg)

	recoveredPayload := OneToOnePayload{}
	err = proto.Unmarshal(unmarshaledMsg, &recoveredPayload)

	s.NoError(err)
	s.Equalf(proto.Equal(&payload, &recoveredPayload), true, "It successfully unmarshal the decrypted message")
}
