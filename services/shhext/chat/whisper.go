package chat

import (
  "fmt"
  "github.com/golang/protobuf/proto"
  whisper "github.com/ethereum/go-ethereum/whisper/whisperv6"
)
const (
  discoveryTopic = "abc"
)

func DirectMessageToWhisper(msg *DirectMessageRPC) (*whisper.NewMessage, error) {

  fmt.Printf("%s\n", msg)
  marshaledPayload, err := proto.Marshal(msg.GetOneToOnePayload())
  if err != nil {
    return nil, err
  }

  return &whisper.NewMessage {
    Payload: marshaledPayload,
    PublicKey: msg.Dst,
  }, nil
}
