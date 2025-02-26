package sigma

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Message struct {
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"ts"`
}

func (m Message) String() string {
	return fmt.Sprintf("[%v] %v: %v", m.Timestamp.Format("Mon Jan 02 15:04:05"), m.Sender, m.Recipient)
}

type EncryptedMessage struct {
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

type ChatSession struct {
	Local      string // name of local client
	Remote     string // name of remote client
	SessionKey []byte // SIGMA-derived session key (32 bytes)
}

// create AES with Galois Counter Mode cipher
func createGCM(session_key []byte) (cipher.AEAD, error) {
	// create cipher block
	block, err := aes.NewCipher(session_key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	// use Galois Counter Mode for symmetric encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}

	return gcm, nil
}

// encrypt a message using AES with Galois Counter Mode for symmetric encryption
func (cs *ChatSession) Encrypt(msg Message) ([]byte, error) {
	msg_data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("error serialising message : %v", err)
	}

	gcm, err := createGCM(cs.SessionKey)
	if err != nil {
		return nil, err
	}

	// create IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(nil, iv); err != nil {
		return nil, fmt.Errorf("error generating iv: %v", err)
	}

	// encrypt
	ciphertext := gcm.Seal(nil, iv, msg_data, nil)

	return json.Marshal(EncryptedMessage{
		IV:         iv,
		Ciphertext: ciphertext,
	})
}

// decrypt ciphertext with AES using Galois Counter Mode
func (cs *ChatSession) Decrypt(data []byte) (Message, error) {
	var encMsg EncryptedMessage
	var msg Message

	if err := json.Unmarshal(data, &encMsg); err != nil {
		return msg, fmt.Errorf("error deserialising encrypted message: %v", err)
	}

	gcm, err := createGCM(cs.SessionKey)
	if err != nil {
		return msg, err
	}

	msg_data, err := gcm.Open(nil, encMsg.IV, encMsg.Ciphertext, nil)
	if err != nil {
		return msg, fmt.Errorf("error decrypting message: %v", err)
	}

	if err := json.Unmarshal(msg_data, &msg); err != nil {
		return msg, fmt.Errorf("error deserializing message: %v", err)
	}

	return msg, nil
}

// SendMessage encrypts and "sends" a message, by returning the encyrpted data
func (cs *ChatSession) SendMessage(content string) ([]byte, error) {
	return cs.Encrypt(
		Message{
			Sender:    cs.Local,
			Recipient: cs.Remote,
			Content:   content,
			Timestamp: time.Now(),
		},
	)
}

func (cs *ChatSession) ReceiveMessage(data []byte) (Message, error) {
	return cs.Decrypt(data)
}

// Sets up a secure chat session, returns each party's chat session and an error if one arises.
// This essentially simulates a SIGMA exchange
//
// assumes both intiator and challenger are already registered to the certificate authority
func EstablishSecureChat(initiator *InitiatorClient, challenger *ChallengerClient) (*ChatSession, *ChatSession, error) {
	if initiator.ca != challenger.ca {
		return nil, nil, fmt.Errorf("both clients should be registered with the same authority")
	}
	// begin SIGMA protocol
	g_x, err := initiator.Initiate()
	if err != nil {
		return nil, nil, fmt.Errorf("could not initiate secure chat session: %v", err)
	}

	// challenger responds
	challenge, err := challenger.Challenge(g_x)
	if err != nil {
		return nil, nil, fmt.Errorf("challenger failed, aborting session: %v", err)
	}

	// initiator responds again and derives its own session key
	resp, err := initiator.Respond(challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("initiator response failed: %v", err)
	}

	// challenger finalises and gets session key
	if err = challenger.Finalise(resp); err != nil {
		return nil, nil, fmt.Errorf("challenger finalisation failed: %v", err)
	}

	init_key, err := initiator.SessionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get session key from initiator: %v", err)
	}
	chall_key, err := challenger.SessionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get session key from challenger: %v", err)
	}

	initiatorSession := ChatSession{initiator.Name, challenger.Name, init_key}
	challengerSession := ChatSession{challenger.Name, initiator.Name, chall_key}

	return &initiatorSession, &challengerSession, nil
}
