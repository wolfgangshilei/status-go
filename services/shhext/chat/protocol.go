package chat

import (
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
)

type ProtocolService struct {
	log        log.Logger
	encryption *EncryptionService
}

func NewProtocolService(encryption *EncryptionService) *ProtocolService {
	return &ProtocolService{
		log:        log.New("package", "status-go/services/sshext.chat"),
		encryption: encryption,
	}
}

func buildDirectMessageProtocol(e *EncryptionResponse) *DirectMessageProtocol {
	ephemeralKey := crypto.CompressPubkey(e.EphemeralKey)
	message := &DirectMessageProtocol{
		Payload: e.EncryptedPayload,
	}
	switch e.EncryptionType {
	case EncryptionTypeDH:
		message.EphemeralKey = &DirectMessageProtocol_DhKey{
			ephemeralKey,
		}
	case EncryptionTypeX3DH:
		message.EphemeralKey = &DirectMessageProtocol_BundleKey{
			ephemeralKey,
		}
		message.BundleId = e.BundleID
	case EncryptionTypeSym:
		message.EphemeralKey = &DirectMessageProtocol_SymKey{
			ephemeralKey,
		}

	}

	return message
}

func (p *ProtocolService) decryptIncomingPayload(myIdentityKey *ecdsa.PrivateKey, theirIdentityKey *ecdsa.PublicKey, msg *DirectMessageProtocol) ([]byte, error) {
	payload := msg.GetPayload()
	// Try Sym Key
	symKeyID := msg.GetSymKey()
	if symKeyID != nil {
		decompressedKey, err := crypto.DecompressPubkey(symKeyID)
		if err != nil {
			return nil, err
		}
		return p.encryption.DecryptSymmetricPayload(theirIdentityKey, decompressedKey, payload)
	}

	// Try X3DH
	x3dhKey := msg.GetBundleKey()
	bundleID := msg.GetBundleId()
	if x3dhKey != nil {
		decompressedKey, err := crypto.DecompressPubkey(symKeyID)
		if err != nil {
			return nil, err
		}
		return p.encryption.DecryptWithX3DH(myIdentityKey, theirIdentityKey, decompressedKey, bundleID, payload)

	}

	// Try DH
	dhKey := msg.GetDhKey()
	if dhKey != nil {
		decompressedKey, err := crypto.DecompressPubkey(dhKey)
		if err != nil {
			return nil, err
		}
		return p.encryption.DecryptWithDH(myIdentityKey, decompressedKey, payload)

	}

	return nil, errors.New("No key specified")
}

func (p *ProtocolService) addBundleAndMarshal(myIdentityKey *ecdsa.PrivateKey, msg *ProtocolMessage) ([]byte, error) {
	// Get a bundle
	bundle, err := p.encryption.CreateBundle(myIdentityKey)
	if err != nil {
		p.log.Error("encryption-service", "error creating bundle", err)
		return nil, err
	}

	msg.Bundle = bundle

	// marshal for sending to wire
	marshaledMessage, err := proto.Marshal(msg)
	if err != nil {
		p.log.Error("encryption-service", "error marshaling message", err)
		return nil, err
	}

	return marshaledMessage, nil
}

func (p *ProtocolService) BuildPublicMessage(myIdentityKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {

	// Build message not encrypted
	protocolMessage := &ProtocolMessage{
		MessageType: &ProtocolMessage_PublicMessage{
			payload,
		},
	}

	return p.addBundleAndMarshal(myIdentityKey, protocolMessage)
}

func (p *ProtocolService) BuildDirectMessage(myIdentityKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey, payload []byte) ([]byte, error) {

	// Encrypt payload
	encryptionResponse, err := p.encryption.EncryptPayload(theirPublicKey, myIdentityKey, payload)
	if err != nil {
		p.log.Error("encryption-service", "error encrypting payload", err)
		return nil, err
	}

	// Build message
	protocolMessage := &ProtocolMessage{
		MessageType: &ProtocolMessage_DirectMessage{
			DirectMessage: buildDirectMessageProtocol(encryptionResponse),
		},
	}

	return p.addBundleAndMarshal(myIdentityKey, protocolMessage)

}

func (p *ProtocolService) HandleMessage(myIdentityKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey, payload []byte) ([]byte, error) {
	// Unmarshal message
	protocolMessage := &ProtocolMessage{}

	err := proto.Unmarshal(payload, protocolMessage)

	if err != nil {
		return nil, err
	}

	// Process bundle
	bundle := protocolMessage.GetBundle()

	if bundle != nil {
		// Should we stop processing if the bundle cannot be verified?
		err := p.encryption.ProcessPublicBundle(bundle)
		if err != nil {
			return nil, err
		}
	}

	// Check if it's a public message
	publicMessage := protocolMessage.GetPublicMessage()
	if publicMessage != nil {
		// Nothing to do, as already in cleartext
		return publicMessage, nil
	}

	// Decrypt message
	directMessage := protocolMessage.GetDirectMessage()
	if directMessage != nil {
		return p.decryptIncomingPayload(myIdentityKey, theirPublicKey, directMessage)
	}

	// Return error
	return nil, errors.New("No payload")

}
