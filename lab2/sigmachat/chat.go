package sigmachat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/yu-val-weiss/p79_cryptography_engineering/lab2/sigma"
)

// Defines a Message sent with SIGMA-powered chat client
type Message struct {
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"ts"`
}

// convenience init function for a new [Message]
func NewMessage(sender, recipient, content string) Message {
	return Message{sender, recipient, content, time.Now()}
}

// converts a [Message] to string
//
//	// format example
//	[Fri Feb 28 19:02:05] Alice -> Bob: Hi Bob!
func (m Message) String() string {
	return fmt.Sprintf("[%v] %v -> %v: %v", m.Timestamp.Format("Mon Jan 02 15:04:05"), m.Sender, m.Recipient, m.Content)
}

// hidden helper struct for encrypted messages, used for encoding/decoding to bytes
type encryptedMessage struct {
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

// exported pointer type for a chat session, used to send and receive messages
type ChatSession = *chatSession

// struct for a chatSession, through which chatting occurs
//
// unexported so cannot create one manually, only through [EstablishSecureChat]
type chatSession struct {
	local      string // name of local client
	remote     string // name of remote client
	sessionKey []byte // SIGMA-derived session key (32 bytes)
}

// create a symmetric cipher instance
//
// uses AES with Galois Counter Mode
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
//
// returns data in []byte form that should be 'sent'
func (cs *chatSession) encrypt(msg Message) ([]byte, error) {
	msg_data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("error serialising message : %v", err) // shouldn't happen
	}

	gcm, err := createGCM(cs.sessionKey)
	if err != nil {
		return nil, err // shouldn't happen
	}

	// create IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("error generating iv: %v", err) // shouldn't happen
	}

	// encrypt
	ciphertext := gcm.Seal(nil, iv, msg_data, nil)

	return json.Marshal(encryptedMessage{
		IV:         iv,
		Ciphertext: ciphertext,
	})
}

// decrypt ciphertext with AES using Galois Counter Mode
//
// returns a [Message]
func (cs *chatSession) decrypt(data []byte) (Message, error) {
	var encMsg encryptedMessage
	var msg Message

	if err := json.Unmarshal(data, &encMsg); err != nil {
		return msg, fmt.Errorf("error deserialising encrypted message: %v", err)
	}

	gcm, err := createGCM(cs.sessionKey)
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

// Encrypts and "sends" a message, by returning the encrypted data
func (cs *chatSession) SendMessage(content string) ([]byte, error) {
	return cs.encrypt(NewMessage(cs.local, cs.remote, content))
}

// "receives" a message, and Decrypts it, returning the [Message] struct represented
func (cs *chatSession) ReceiveMessage(data []byte) (Message, error) {
	return cs.decrypt(data)
}

// Sets up a secure chat session, returns each party's chat session and an error if one arises.
// This essentially simulates a SIGMA exchange
func EstablishSecureChat(initiator sigma.InitiatorClient, challenger sigma.ChallengerClient) (ChatSession, ChatSession, error) {
	if !sigma.CheckCAMatch(initiator, challenger) {
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

	initiatorSession := chatSession{initiator.Name(), challenger.Name(), init_key}
	challengerSession := chatSession{challenger.Name(), initiator.Name(), chall_key}

	return &initiatorSession, &challengerSession, nil
}
