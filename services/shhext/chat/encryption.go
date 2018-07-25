package chat

import (
	"crypto/ecdsa"
	"errors"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/status-im/status-go/crypto"
)

var publicKeyPrefix = []byte{0x10, 0x11}
var privateBundleKeyPrefix = []byte{0x10, 0x12}
var symmetricKeyKeyPrefix = []byte{0x10, 0x13}

var KeyNotFoundError = errors.New("Key not found")

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
func (s *EncryptionService) GetAnyPrivateBundle() (*Bundle, error) {
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

func (s *EncryptionService) GetPrivateBundle(bundleId []byte) (*BundleContainer, error) {
	byteBundle, err := s.db.Get(append(privateBundleKeyPrefix, bundleId...), nil)
	if err != nil {
		return nil, err
	}

	bundleContainer := BundleContainer{}

	err = proto.Unmarshal(byteBundle, &bundleContainer)

	return &bundleContainer, err
}

// Pick any established key, any key, and return the ephemeral key used
func (s *EncryptionService) GetAnySymmetricKey(pk []byte) ([]byte, *ecdsa.PublicKey, error) {
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

func (s *EncryptionService) PutSymmetricKey(dst []byte, id []byte, key []byte) error {
	return s.db.Put(symmetricKeyKey(append(dst, id...)), key, nil)
}

func (s *EncryptionService) GetPublicBundle(pk []byte) (*Bundle, error) {
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

func (s *EncryptionService) keyFromX3DH(pk []byte, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	bundle, err := s.GetPublicBundle(pk)

	if err != nil {
		return nil, nil, err
	}

	if bundle == nil {
		return nil, nil, nil
	}

	return PerformActiveX3DH(bundle, privateKey)
}

func (s *EncryptionService) keyFromDH(pk *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {

	return PerformActiveDH(pk)
}

func (s *EncryptionService) CreateBundle(privateKey *ecdsa.PrivateKey) (*Bundle, error) {
	bundle, err := s.GetAnyPrivateBundle()
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

func (s *EncryptionService) DecryptSymmetricPayload(src *ecdsa.PublicKey, bundleId []byte, payload []byte) ([]byte, error) {
	compressedSrc := ecrypto.CompressPubkey(src)

	symmetricKey, _, err := s.GetAnySymmetricKey(compressedSrc)

	if symmetricKey == nil {
		return nil, KeyNotFoundError
	}

	if err != nil {
		return nil, err
	}

	return crypto.DecryptSymmetric(symmetricKey, payload)

}

// Decrypt message sent with a DH key exchange, throw away the key after decryption
func (s *EncryptionService) DecryptWithDH(myIdentityKey *ecdsa.PrivateKey, theirEphemeralKey *ecdsa.PublicKey, payload []byte) ([]byte, error) {
	key, err := PerformDH(
		ecies.ImportECDSA(myIdentityKey),
		ecies.ImportECDSAPublic(theirEphemeralKey),
	)
	if err != nil {
		return nil, err
	}

	return crypto.DecryptSymmetric(key, payload)

}

// Decrypt message sent with a X3DH key exchange, store the key for future exchanges
func (s *EncryptionService) DecryptWithX3DH(myIdentityKey *ecdsa.PrivateKey, theirIdentityKey *ecdsa.PublicKey, theirEphemeralKey *ecdsa.PublicKey, ourBundleId []byte, payload []byte) ([]byte, error) {
	myBundle, err := s.GetPrivateBundle(ourBundleId)
	if err != nil {
		return nil, err
	}

	signedPreKey, err := ecrypto.ToECDSA(myBundle.GetPrivateSignedPreKey())
	if err != nil {
		return nil, err
	}

	key, err := PerformPassiveX3DH(
		theirIdentityKey,
		signedPreKey,
		theirEphemeralKey,
		myIdentityKey,
	)
	if err != nil {
		return nil, err
	}

	// We encrypt the payload
	encryptedPayload, err := crypto.DecryptSymmetric(key, payload)
	if err != nil {
		return nil, err
	}

	// And we store the key for later use
	err = s.PutSymmetricKey(
		ecrypto.CompressPubkey(theirIdentityKey),
		ecrypto.CompressPubkey(theirEphemeralKey),
		key)

	if err != nil {
		return nil, err
	}
	return encryptedPayload, nil
}

func (s *EncryptionService) EncryptPayload(dst *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	var symmetricKey []byte
	var ephemeralKey *ecdsa.PublicKey
	var compressedDst = ecrypto.CompressPubkey(dst)
	var err error

	// This should be in a transaction or similar

	s.log.Info("Getting  symmetric")
	// Check if we have already a key established
	symmetricKey, ephemeralKey, err = s.GetAnySymmetricKey(compressedDst)
	if err != nil {
		return nil, nil, err
	}

	s.log.Info("Trying  x3dh")
	// If not there try with a bundle
	if symmetricKey == nil {
		symmetricKey, ephemeralKey, err = s.keyFromX3DH(compressedDst, privateKey, payload)
	}
	if err != nil {
		return nil, nil, err
	}

	// keys from DH should not be re-used, so we don't store them
	if symmetricKey == nil {
		s.log.Info("executing  DH")
		symmetricKey, ephemeralKey, err := s.keyFromDH(dst, privateKey, payload)
		if err != nil {
			return nil, nil, err
		}
		encryptedPayload, err := crypto.EncryptSymmetric(symmetricKey, payload)
		if err != nil {
			return nil, nil, err
		}
		return encryptedPayload, ephemeralKey, nil
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
		compressedEphemeral := ecrypto.CompressPubkey(ephemeralKey)
		err = s.PutSymmetricKey(compressedDst, compressedEphemeral, symmetricKey)
		if err != nil {
			return nil, nil, err
		}
	}

	s.log.Info("Encrypted payoad  payload")
	return encryptedPayload, ephemeralKey, nil
}
