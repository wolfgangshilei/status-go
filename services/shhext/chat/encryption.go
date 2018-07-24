package chat

import (
	"crypto/ecdsa"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/status-im/status-go/crypto"
)

var publicKeyPrefix = []byte{0x10, 0x11}
var privateBundleKeyPrefix = []byte{0x10, 0x12}
var symmetricKeyKeyPrefix = []byte{0x10, 0x13}

type EncryptionService struct {
	log log.Logger
	db  *leveldb.DB
}

func NewEncryptionService(db *leveldb.DB) *EncryptionService {
	return &EncryptionService{
		log: log.New("package", "status-go/services/sshext.chat"),
		db:  db,
	}
}

func publicBundleKey(key []byte) []byte {
	return append(publicKeyPrefix, key...)
}

func privateBundleKey(key []byte) []byte {
	return append(privateBundleKeyPrefix, key...)
}

func symmetricKeyKey(key []byte) []byte {
	return append(symmetricKeyKeyPrefix, key...)
}

func (s *EncryptionService) AddPublicBundle(b *Bundle) error {

	marshaledBundle, err := proto.Marshal(b)
	if err != nil {
		return err
	}

	err = s.db.Put(publicBundleKey(b.GetIdentity()), marshaledBundle, nil)
	if err != nil {
		return err
	}

	return nil
}

// Return the only bundle for now
func (s *EncryptionService) GetPrivateBundle() (*Bundle, error) {
	var bundleContainer *BundleContainer
	iter := s.db.NewIterator(util.BytesPrefix(privateBundleKeyPrefix), nil)

	for iter.Next() {
		value := iter.Value()
		err := proto.Unmarshal(value, bundleContainer)
		if err != nil {
			return nil, err
		}
		iter.Release()
		return bundleContainer.GetBundle(), nil

	}
	return nil, nil
}

func (s *EncryptionService) AddPrivateBundle(b *BundleContainer) error {
	marshaledBundle, err := proto.Marshal(b)
	if err != nil {
		return err
	}

	err = s.db.Put(privateBundleKey(b.GetBundle().GetSignedPreKey()), marshaledBundle, nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *EncryptionService) GetSymmetricKey(pk []byte) ([]byte, error) {
	return s.db.Get(symmetricKeyKey(pk), nil)
}

func (s *EncryptionService) PutSymmetricKey(pk []byte, key []byte) error {
	return s.db.Put(symmetricKeyKey(pk), key, nil)
}

func (s *EncryptionService) GetPublicBundle(pk []byte) (*Bundle, error) {
	s.log.Info("bytebundle x3dh")
	byteBundle, err := s.db.Get(publicBundleKey(pk), nil)
	s.log.Info("bytebundle Get", byteBundle, err)
	if byteBundle == nil {
		return nil, nil
	}

	s.log.Info("unmarshalling bytebundle")
	bundle := &Bundle{}
	err = proto.Unmarshal(byteBundle, bundle)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (s *EncryptionService) keyFromX3DH(pk []byte, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	s.log.Info("getting public bundle")
	bundle, _ := s.GetPublicBundle(pk)

	//if err != nil {
	//		return nil, nil, err
	//	}

	if bundle == nil {
		return nil, nil, nil
	}

	s.log.Info("performing x3dh")
	return PerformActiveX3DH(bundle, privateKey)
}

func (s *EncryptionService) keyFromDH(pk *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {

	return PerformActiveDH(pk)
}

func (s *EncryptionService) GetBundle(privateKey *ecdsa.PrivateKey) (*Bundle, error) {
	bundle, err := s.GetPrivateBundle()
	if err != nil {
		return nil, err
	}

	if bundle != nil {
		return bundle, nil
	}
	// needs transaction/mutex
	bundleContainer, err := NewBundleContainer(privateKey)
	if err != nil {
		return nil, err
	}

	err = s.AddPrivateBundle(bundleContainer)
	if err != nil {
		return nil, err
	}

	return bundleContainer.GetBundle(), nil
}

func (s *EncryptionService) EncryptPayload(pk []byte, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	var symmetricKey []byte
	var ephemeralKey *ecdsa.PublicKey
	// This should be in a transaction or similar

	s.log.Info("Unmarshaling pubkey")
	publicKey, err := ecrypto.UnmarshalPubkey(pk)
	if err != nil {
		return nil, nil, err
	}

	s.log.Info("Getting  symmetric")
	// Check if we have already a key
	symmetricKey, _ = s.GetSymmetricKey(pk)
	//if err != nil {
	//	return nil, nil, err
	//}

	s.log.Info("Trying  x3dh")
	// If not there try with a bundle
	if symmetricKey == nil {
		s.log.Info("executing  x3dh")
		symmetricKey, ephemeralKey, err = s.keyFromX3DH(pk, privateKey, payload)
	}
	if err != nil {
		return nil, nil, err
	}

	s.log.Info("Trying  DH")
	if symmetricKey == nil {
		s.log.Info("executing  DH")
		symmetricKey, ephemeralKey, err = s.keyFromDH(publicKey, privateKey, payload)
	}
	if err != nil {
		return nil, nil, err
	}

	s.log.Info("Encrypting  payload", symmetricKey)
	encryptedPayload, err := crypto.EncryptSymmetric(symmetricKey, payload)

	if err != nil {
		return nil, nil, err
	}

	s.log.Info("Storing  symmetric key")
	// If we just generated the key, we save it
	if ephemeralKey != nil {
		err = s.PutSymmetricKey(pk, symmetricKey)
		if err != nil {
			return nil, nil, err
		}
	}

	s.log.Info("Encrypted payoad  payload")
	return encryptedPayload, ephemeralKey, nil
}
