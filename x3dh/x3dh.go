package x3dh

import (
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/golang/protobuf/jsonpb"
)

const (
	sskLen = 16
)

func (bundle Bundle) ToJSON() (string, error) {
	ma := jsonpb.Marshaler{}
	return ma.MarshalToString(&bundle)
}

func FromJSON(str string) (*Bundle, error) {
	var bundle Bundle
	err := jsonpb.UnmarshalString(str, &bundle)
	return &bundle, err
}

func NewBundle(identity *ecdsa.PrivateKey) (*Bundle, *ecdsa.PrivateKey, error) {
	preKey, err := crypto.GenerateKey()

	if err != nil {
		return nil, nil, err
	}

	compressedPreKey := crypto.CompressPubkey(&preKey.PublicKey)
	compressedIdentityKey := crypto.CompressPubkey(&identity.PublicKey)

	signature, err := crypto.Sign(crypto.Keccak256(compressedPreKey), identity)

	if err != nil {
		return nil, nil, err
	}

	bundle := Bundle{
		Identity:     compressedIdentityKey,
		SignedPreKey: compressedPreKey,
		Signature:    signature,
	}

	return &bundle, preKey, nil
}

func verifyBundle(bundle *Bundle, bundleIdentityKey *ecdsa.PublicKey) error {

	recoveredKey, err := crypto.SigToPub(
		crypto.Keccak256(bundle.GetSignedPreKey()),
		bundle.GetSignature(),
	)

	if err != nil {
		return err
	}

	if crypto.PubkeyToAddress(*recoveredKey) != crypto.PubkeyToAddress(*bundleIdentityKey) {
		return errors.New("Identity key and signature mismatch")
	}

	return nil
}

func performDH(privateKey *ecies.PrivateKey, publicKey *ecies.PublicKey) ([]byte, error) {
  return  privateKey.GenerateShared(
    publicKey,
    sskLen,
    sskLen,
  )
}

func getSharedSecret(dh1 []byte, dh2 []byte, dh3 []byte) []byte {
  secretInput := append(append(dh1, dh2...), dh3...)

  return crypto.Keccak256(secretInput)
}

// Initiate an X3DH session
func x3dhActive(
	myIdentityKey *ecies.PrivateKey,
	theirSignedPreKey *ecies.PublicKey,
	myEphemeralKey *ecies.PrivateKey,
	theirIdentityKey *ecies.PublicKey,
) ([]byte, error) {
	dh1, err := performDH(myIdentityKey, theirSignedPreKey)
	if err != nil {
		return nil, err
	}

	dh2, err := performDH(myEphemeralKey, theirIdentityKey)
	if err != nil {
		return nil, err
	}

	dh3, err := performDH(myEphemeralKey, theirSignedPreKey)
	if err != nil {
		return nil, err
	}

	return getSharedSecret(dh1, dh2, dh3), nil
}

// Respond to an initiated X3DH session
func x3dhPassive(
	theirIdentityKey *ecies.PublicKey,
	mySignedPreKey *ecies.PrivateKey,
	theirEphemeralKey *ecies.PublicKey,
	myIdentityKey *ecies.PrivateKey,
) ([]byte, error) {
	dh1, err := performDH(mySignedPreKey,theirIdentityKey)
	if err != nil {
		return nil, err
	}

	dh2, err := performDH(myIdentityKey, theirEphemeralKey)
	if err != nil {
		return nil, err
	}

	dh3, err := performDH(mySignedPreKey, theirEphemeralKey)
	if err != nil {
		return nil, err
	}

	return getSharedSecret(dh1, dh2, dh3), nil
}

// Take someone elses' bundle, calculate shared secret.
// returns the shared secret and the ephemeral key used.
func PerformActiveX3DH(bundle *Bundle, prv *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {

	bundleIdentityKey, err := crypto.DecompressPubkey(bundle.GetIdentity())
	if err != nil {
		return nil, nil, err
	}

	bundleSignedPreKey, err := crypto.DecompressPubkey(bundle.GetIdentity())
	if err != nil {
		return nil, nil, err
	}

	err = verifyBundle(bundle, bundleIdentityKey)

	if err != nil {
		return nil, nil, err
	}

	ephemeralKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

        sharedSecret, err := x3dhActive(
		ecies.ImportECDSA(prv),
		ecies.ImportECDSAPublic(bundleSignedPreKey),
		ecies.ImportECDSA(ephemeralKey),
		ecies.ImportECDSAPublic(bundleIdentityKey),
	)
	if err != nil {
		return nil, nil, err
	}

        return sharedSecret, ephemeralKey, nil
}

// They used our bundle, with ID of the signedPreKey, we loaded our identity key and
// the correct signedPreKey and we perform X3DH
func PerformPassiveX3DH(theirIdentityKey *ecdsa.PublicKey, mySignedPreKey *ecdsa.PrivateKey, theirEphemeralKey *ecdsa.PublicKey, myPrivateKey *ecdsa.PrivateKey) ([]byte, error) {

  sharedSecret, err := x3dhPassive(
    ecies.ImportECDSAPublic(theirIdentityKey),
    ecies.ImportECDSA(mySignedPreKey),
    ecies.ImportECDSAPublic(theirEphemeralKey),
    ecies.ImportECDSA(myPrivateKey),
  )
  if err != nil {
    return nil, err
  }

  return sharedSecret, nil
}
