package chat

import (
	"crypto/ecdsa"
	"errors"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"

	"github.com/status-im/status-go/services/shhext/chat/crypto"
)

var KeyNotFoundError = errors.New("Key not found")

type EncryptionService struct {
	log         log.Logger
	persistence PersistenceServiceInterface
}

func NewEncryptionService(p *PersistenceService) *EncryptionService {
	return &EncryptionService{
		log:         log.New("package", "status-go/services/sshext.chat"),
		persistence: p,
	}
}

func (s *EncryptionService) keyFromX3DH(theirPublicKey *ecdsa.PublicKey, myIdentityKey *ecdsa.PrivateKey, payload []byte) ([]byte, []byte, *ecdsa.PublicKey, error) {

	bundle, err := s.persistence.GetPublicBundle(theirPublicKey)

	if err != nil {
		return nil, nil, nil, err
	}

	if bundle == nil {
		return nil, nil, nil, nil
	}

	payload, ephemeralKey, err := PerformActiveX3DH(bundle, myIdentityKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return payload, bundle.GetSignedPreKey(), ephemeralKey, nil
}

func (s *EncryptionService) keyFromDH(pk *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {

	return PerformActiveDH(pk)
}

func (s *EncryptionService) CreateBundle(privateKey *ecdsa.PrivateKey) (*Bundle, error) {
	bundle, err := s.persistence.GetAnyPrivateBundle()
	if err != nil {
		return nil, err
	}

	if bundle != nil {
		return bundle, nil
	}

	// needs transaction/mutex to avoid creating multiple bundles
	// although not a problem
	bundleContainer, err := NewBundleContainer(privateKey)
	if err != nil {
		return nil, err
	}

	err = s.persistence.AddPrivateBundle(bundleContainer)
	if err != nil {
		return nil, err
	}

	return bundleContainer.GetBundle(), nil
}

func (s *EncryptionService) DecryptSymmetricPayload(src *ecdsa.PublicKey, ephemeralKey *ecdsa.PublicKey, payload []byte) ([]byte, error) {

	symmetricKey, err := s.persistence.GetSymmetricKey(src, ephemeralKey)
	if err != nil {
		return nil, err
	}

	if symmetricKey == nil {
		return nil, KeyNotFoundError
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
	myBundle, err := s.persistence.GetPrivateBundle(ourBundleId)
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
	err = s.persistence.AddSymmetricKey(
		theirIdentityKey,
		theirEphemeralKey,
		key)

	if err != nil {
		return nil, err
	}
	return encryptedPayload, nil
}

const (
	EncryptionTypeDH   = "dh"
	EncryptionTypeSym  = "sym"
	EncryptionTypeX3DH = "x3dh"
)

type EncryptionResponse struct {
	EphemeralKey     *ecdsa.PublicKey
	EncryptionType   string
	EncryptedPayload []byte
	BundleId         []byte
}

func (s *EncryptionService) ProcessPublicBundle(b *Bundle) error {
	// Make sure the bundle belongs to who signed it
	err := VerifyBundle(b)
	if err != nil {
		return err
	}

	return s.persistence.AddPublicBundle(b)
}

func (s *EncryptionService) EncryptPayload(theirIdentityKey *ecdsa.PublicKey, myIdentityKey *ecdsa.PrivateKey, payload []byte) (*EncryptionResponse, error) {
	var symmetricKey []byte
	// The ephemeral key used to encrypt the payload
	var ourEphemeralKey *ecdsa.PublicKey
	// The bundle used
	var bundleId []byte

	encryptionType := EncryptionTypeSym

	// This should be in a transaction or similar

	// Check if we have already a key established
	symmetricKey, ourEphemeralKey, err := s.persistence.GetAnySymmetricKey(theirIdentityKey)
	if err != nil {
		return nil, err
	}

	// If not there try with a bundle and store the key
	if symmetricKey == nil {
		encryptionType = EncryptionTypeX3DH
		symmetricKey, bundleId, ourEphemeralKey, err = s.keyFromX3DH(theirIdentityKey, myIdentityKey, payload)
		if ourEphemeralKey != nil {
			err = s.persistence.AddSymmetricKey(theirIdentityKey, ourEphemeralKey, symmetricKey)
			if err != nil {
				return nil, err
			}
		}
	}
	if err != nil {
		return nil, err
	}

	// keys from DH should not be re-used, so we don't store them
	if symmetricKey == nil {
		encryptionType = EncryptionTypeDH
		symmetricKey, ourEphemeralKey, err = s.keyFromDH(theirIdentityKey, myIdentityKey, payload)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := crypto.EncryptSymmetric(symmetricKey, payload)
	if err != nil {
		return nil, err
	}

	return &EncryptionResponse{
		EncryptedPayload: encryptedPayload,
		EphemeralKey:     ourEphemeralKey,
		EncryptionType:   encryptionType,
		BundleId:         bundleId,
	}, nil
}
