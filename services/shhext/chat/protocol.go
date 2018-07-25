package chat

import (
	"crypto/ecdsa"
	//	"github.com/ethereum/go-ethereum/crypto"
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

func (p *ProtocolService) BuildDirectMessage(myPrivateKey *ecdsa.PrivateKey, theirPublicKey *ecdsa.PublicKey, payload []byte) ([]byte, error) {

	// Encrypt payload
	encryptionResponse, err := p.encryption.EncryptPayload(theirPublicKey, myPrivateKey, payload)
	if err != nil {
		return nil, err
	}

	// Get a bundle
	bundle, err := p.encryption.CreateBundle(myPrivateKey)
	if err != nil {
		return nil, err
	}

	protocolMessage := &ProtocolMessage{
		Bundle: bundle,
		MessageType: &ProtocolMessage_DirectMessage{
			DirectMessage: &DirectMessageProtocol{
				// Can we return already compressed
				//				EphemeralKey: crypto.CompressPubkey(ephemeralKey),
				Payload: &DirectMessageProtocol_OneToOnePayload{
					encryptionResponse.EncryptedPayload,
				},
			},
		},
	}

	marshaledMessage, err := proto.Marshal(protocolMessage)
	if err != nil {
		return nil, err
	}

	return marshaledMessage, nil
}

func (p *ProtocolService) HandleMessage(myPrivateKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	return nil, nil

}
