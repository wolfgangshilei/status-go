package chat

import (
	"crypto/ecdsa"

        "github.com/golang/protobuf/proto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/syndtr/goleveldb/leveldb"

        "github.com/status-im/status-go/crypto"
      )

type EncryptionService struct {
  log  log.Logger
  db   *leveldb.DB
  privateKey *ecdsa.PrivateKey
}

func NewEncryptionService(db *leveldb.DB) *EncryptionService {
  return &EncryptionService{
      log:             log.New("package", "status-go/services/sshext.chat"),
      db:   db,
    }
}

func publicBundleKey(key []byte) []byte {
  return append([]byte{0x10, 0x11}, key...)
}

func privateBundleKey(key []byte) []byte {
  return append([]byte{0x10, 0x12}, key...)
}

func symmetricKeyKey(key []byte) []byte {
  return append([]byte{0x10, 0x13}, key...)
}

func (s *EncryptionService) AddPublicBundle(b *Bundle) error {

  marshaledBundle, err :=  proto.Marshal(b)
  if err != nil {
    return err
  }

  err = s.db.Put(publicBundleKey(b.GetIdentity()), marshaledBundle, nil)
  if err != nil {
    return err
  }

  return nil
}

func (s *EncryptionService) AddPrivateBundle(b *BundleContainer) error {
  marshaledBundle, err :=  proto.Marshal(b)
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
  byteBundle, err := s.db.Get(publicBundleKey(pk), nil)
  if err != nil {
    return nil, err
  }

  bundle := &Bundle{}
  err = proto.Unmarshal(byteBundle, bundle)
  if err != nil {
    return nil, err
  }

  return bundle, nil
}

func (s *EncryptionService) keyFromX3DH(pk []byte, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
  bundle, err := s.GetPublicBundle(pk)

  if err != nil {
    return nil, nil, err
  }

  if bundle == nil {
    return nil, nil, nil
  }

  return PerformActiveX3DH(bundle, s.privateKey)
}

func (s *EncryptionService) keyFromDH(pk []byte, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
  bundle, err := s.GetPublicBundle(pk)

  if err != nil {
    return nil, nil, err
  }

  if bundle == nil {
    return nil, nil, nil
  }

  return PerformActiveX3DH(bundle, s.privateKey)
}


func (s *EncryptionService) GetBundle() (*BundleContainer, error) {
  // needs transaction/mutex
  bundle, err := NewBundleContainer(s.privateKey)
  if err != nil {
    return nil, err
    }

  err = s.AddPrivateBundle(bundle)
  if err != nil {
    return nil, err
  }

  return bundle, nil
}

func (s *EncryptionService) EncryptPayload(pk []byte, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
  var symmetricKey []byte
  var publicKey *ecdsa.PublicKey
  // This should be in a transaction or similar

  // Check if we have already a key
  symmetricKey, err := s.GetSymmetricKey(pk)
  if err != nil {
    return nil, nil, err
  }

  // If not there try with a bundle
  if symmetricKey != nil {
    symmetricKey, publicKey, err = s.keyFromX3DH(pk, payload)
  }
  if err != nil {
    return nil, nil, err
  }

  encryptedPayload, err := crypto.EncryptSymmetric(symmetricKey, payload)

  if err != nil {
    return nil, nil, err
  }

  if symmetricKey != nil {
    symmetricKey, publicKey, err = s.keyFromDH(pk, payload)
  }
  if err != nil {
    return nil, nil, err
  }

  // If we just generated the key, we save it
  if symmetricKey != nil {
    err = s.PutSymmetricKey(pk, symmetricKey)
    if err != nil {
      return nil, nil, err
    }
  }

  return encryptedPayload, publicKey, nil
}
