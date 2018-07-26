package chat

import (
	"crypto/ecdsa"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

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

func symmetricKeyKey(key []byte) []byte {
	return append(symmetricKeyKeyPrefix, key...)
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

// Return the only bundle for now
func (s *PersistenceService) GetAnyPrivateBundle() (*Bundle, error) {
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

func (s *PersistenceService) GetPrivateBundle(bundleId []byte) (*BundleContainer, error) {
	byteBundle, err := s.db.Get(append(privateBundleKeyPrefix, bundleId...), nil)
	if err != nil {
		return nil, err
	}

	bundleContainer := BundleContainer{}

	err = proto.Unmarshal(byteBundle, &bundleContainer)

	return &bundleContainer, err
}

// Pick any established key, any key, and return the ephemeral key used
func (s *PersistenceService) GetAnySymmetricKey(pk []byte) ([]byte, *ecdsa.PublicKey, error) {
	iter := s.db.NewIterator(util.BytesPrefix(append(symmetricKeyKeyPrefix, pk...)), nil)
	for iter.Next() {
		key := iter.Key()[len(symmetricKeyKeyPrefix)+len(pk):]
		ephemeralKey, err := ecrypto.DecompressPubkey(key)
		if err != nil {
			return nil, nil, err
		}

		value := iter.Value()
		iter.Release()
		return value, ephemeralKey, nil
	}
	return nil, nil, nil
}

func (s *PersistenceService) GetSymmetricKey(dst []byte, id []byte) ([]byte, error) {
	return s.db.Get(symmetricKeyKey(append(dst, id...)), nil)
}

func (s *PersistenceService) PutSymmetricKey(dst []byte, id []byte, key []byte) error {
	return s.db.Put(symmetricKeyKey(append(dst, id...)), key, nil)
}

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

func (s *PersistenceService) GetPublicBundle(pk []byte) (*Bundle, error) {
	byteBundle, err := s.db.Get(publicBundleKey(pk), nil)

	if err != nil && err != lerrors.ErrNotFound {
		return nil, err
	}

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
