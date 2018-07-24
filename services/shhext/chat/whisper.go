package chat

import (
  "github.com/ethereum/go-ethereum/common/hexutil"
  whisper "github.com/ethereum/go-ethereum/whisper/whisperv6"
)

var discoveryTopic = whisper.TopicType{0xf8, 0x94, 0x6a, 0xac}

func DirectMessageToWhisper(rpcMessage *OneToOneRPC, payload []byte) (*whisper.NewMessage, error) {

  // Some field use their own byte type so they need to be converted
  publicKey := hexutil.Bytes{}
  err := publicKey.UnmarshalText([]byte(rpcMessage.Dst))
  if err != nil {
    return nil, err
  }

  return &whisper.NewMessage {
    PublicKey: publicKey,
    Payload: payload,
    Topic: discoveryTopic,
    TTL: 10,
    PowTarget: 0.002,
    PowTime: 1,
  }, nil
}
