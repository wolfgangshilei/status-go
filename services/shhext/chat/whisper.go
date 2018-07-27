package chat

import (
	whisper "github.com/ethereum/go-ethereum/whisper/whisperv6"
)

var discoveryTopic = whisper.TopicType{0xf8, 0x94, 0x6a, 0xac}

func DirectMessageToWhisper(msg *whisper.NewMessage, payload []byte) *whisper.NewMessage {

	msg.Topic = discoveryTopic
	msg.TTL = 10
	msg.PowTarget = 0.002
	msg.PowTime = 1
	return msg
}
