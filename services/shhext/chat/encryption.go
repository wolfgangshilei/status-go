package chat

import (
	"crypto/ecdsa"
	"errors"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"

	"github.com/status-im/status-go/crypto"
)

var publicKeyPrefix = []byte{0x10, 0x11}
var privateBundleKeyPrefix = []byte{0x10, 0x12}
var symmetricKeyKeyPrefix = []byte{0x10, 0x13}

var KeyNotFoundError = errors.New("Key not found")

type EncryptionService struct {
	log         log.Logger
	persistence *PersistenceService
}

func NewEncryptionService(p *PersistenceService) *EncryptionService {
	return &EncryptionService{
		log:         log.New("package", "status-go/services/sshext.chat"),
		persistence: p,
	}
}

func (s *EncryptionService) keyFromX3DH(pk []byte, privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, *ecdsa.PublicKey, error) {
	bundle, err := s.persistence.GetPublicBundle(pk)

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
	bundle, err := s.persistence.GetAnyPrivateBundle()
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

	err = s.persistence.AddPrivateBundle(bundleContainer)
	if err != nil {
		return nil, err
	}

	return bundleContainer.GetBundle(), nil
}

func (s *EncryptionService) DecryptSymmetricPayload(src *ecdsa.PublicKey, bundleId []byte, payload []byte) ([]byte, error) {
	compressedSrc := ecrypto.CompressPubkey(src)

	symmetricKey, _, err := s.persistence.GetAnySymmetricKey(compressedSrc)

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
	err = s.persistence.PutSymmetricKey(
		ecrypto.CompressPubkey(theirIdentityKey),
		ecrypto.CompressPubkey(theirEphemeralKey),
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
}

func (s *EncryptionService) EncryptPayload(dst *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, payload []byte) (*EncryptionResponse, error) {
	var symmetricKey []byte
	var ephemeralKey *ecdsa.PublicKey
	encryptionType := EncryptionTypeSym

	compressedDst := ecrypto.CompressPubkey(dst)

	// This should be in a transaction or similar

	s.log.Info("Getting  symmetric")
	// Check if we have already a key established
	symmetricKey, ephemeralKey, err := s.persistence.GetAnySymmetricKey(compressedDst)
	if err != nil {
		return nil, err
	}

	s.log.Info("Trying  x3dh")
	// If not there try with a bundle and store the key
	if symmetricKey == nil {
		encryptionType = EncryptionTypeX3DH
		symmetricKey, ephemeralKey, err = s.keyFromX3DH(compressedDst, privateKey, payload)
		if ephemeralKey != nil {
			compressedEphemeral := ecrypto.CompressPubkey(ephemeralKey)
			err = s.persistence.PutSymmetricKey(compressedDst, compressedEphemeral, symmetricKey)
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
		symmetricKey, ephemeralKey, err = s.keyFromDH(dst, privateKey, payload)
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
		EphemeralKey:     ephemeralKey,
		EncryptionType:   encryptionType,
	}, nil
}
