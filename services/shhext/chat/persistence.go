package chat

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type PersistenceServiceInterface interface {
	GetPublicBundle(*ecdsa.PublicKey) (*Bundle, error)
	AddPublicBundle(*Bundle) error

	GetAnyPrivateBundle() (*Bundle, error)
	GetPrivateBundle([]byte) (*BundleContainer, error)
	AddPrivateBundle(*BundleContainer) error

	GetAnySymmetricKey(*ecdsa.PublicKey) ([]byte, *ecdsa.PublicKey, error)
	GetSymmetricKey(*ecdsa.PublicKey, *ecdsa.PublicKey) ([]byte, error)
	AddSymmetricKey(*ecdsa.PublicKey, *ecdsa.PublicKey, []byte) error
}

var publicKeyPrefix = []byte{0x10, 0x11}
var privateBundleKeyPrefix = []byte{0x10, 0x12}
var symmetricKeyPrefix = []byte{0x10, 0x13}

type PersistenceService struct {
	log log.Logger
	db  *leveldb.DB
}

func publicBundleKey(key []byte) []byte {
	return append(publicKeyPrefix, key...)
}

func privateBundleKey(key []byte) []byte {
	return append(privateBundleKeyPrefix, key...)
}

func symmetricKey(key []byte) []byte {
	return append(symmetricKeyPrefix, key...)
}

func NewPersistenceService(db *leveldb.DB) *PersistenceService {
	return &PersistenceService{
		log: log.New("package", "status-go/services/sshext.chat"),
		db:  db,
	}
}

func (s *PersistenceService) AddPublicBundle(b *Bundle) error {

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

// Get someone else's bundle given their identity
func (s *PersistenceService) GetPublicBundle(publicKey *ecdsa.PublicKey) (*Bundle, error) {
	key := crypto.CompressPubkey(publicKey)

	byteBundle, err := s.db.Get(publicBundleKey(key), nil)

	// Ignore not found errors
	if err != nil && err != lerrors.ErrNotFound {
		return nil, err
	}

	if byteBundle == nil {
		return nil, nil
	}

	bundle := &Bundle{}
	err = proto.Unmarshal(byteBundle, bundle)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

// Get the first private bundle
func (s *PersistenceService) GetAnyPrivateBundle() (*Bundle, error) {
	iter := s.db.NewIterator(util.BytesPrefix(privateBundleKeyPrefix), nil)

	if iter.First() {
		value := iter.Value()
		bundleContainer := &BundleContainer{}
		err := proto.Unmarshal(value, bundleContainer)
		if err != nil {
			return nil, err
		}

		iter.Release()
		return bundleContainer.GetBundle(), nil

	}
	return nil, nil
}

// Get private bundle by id
func (s *PersistenceService) GetPrivateBundle(bundleID []byte) (*BundleContainer, error) {
	byteBundle, err := s.db.Get(append(privateBundleKeyPrefix, bundleID...), nil)
	if err != nil {
		return nil, err
	}

	bundleContainer := BundleContainer{}

	err = proto.Unmarshal(byteBundle, &bundleContainer)

	return &bundleContainer, err
}

// Add your own bundle
func (s *PersistenceService) AddPrivateBundle(b *BundleContainer) error {
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

// Pick any established key, any key, and return the ephemeral key used
func (s *PersistenceService) GetAnySymmetricKey(identityKey *ecdsa.PublicKey) ([]byte, *ecdsa.PublicKey, error) {
	pk := crypto.CompressPubkey(identityKey)

	iter := s.db.NewIterator(util.BytesPrefix(append(symmetricKeyPrefix, pk...)), nil)
	if iter.First() {
		key := iter.Key()[len(symmetricKeyPrefix)+len(pk):]
		ephemeralKey, err := crypto.DecompressPubkey(key)
		if err != nil {
			return nil, nil, err
		}

		value := iter.Value()
		iter.Release()
		return value, ephemeralKey, nil
	}
	return nil, nil, nil
}

func (s *PersistenceService) GetSymmetricKey(identityKey *ecdsa.PublicKey, ephemeralKey *ecdsa.PublicKey) ([]byte, error) {
	pkBytes := crypto.CompressPubkey(identityKey)
	ekBytes := crypto.CompressPubkey(ephemeralKey)

	return s.db.Get(symmetricKey(append(pkBytes, ekBytes...)), nil)
}

func (s *PersistenceService) AddSymmetricKey(identityKey *ecdsa.PublicKey, ephemeralKey *ecdsa.PublicKey, key []byte) error {
	pkBytes := crypto.CompressPubkey(identityKey)

	ekBytes := crypto.CompressPubkey(ephemeralKey)

	return s.db.Put(symmetricKey(append(pkBytes, ekBytes...)), key, nil)
}
