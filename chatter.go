// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	"fmt"
	//un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet        *KeyPair
	PartnerDHRatchet   *PublicKey
	RootChain          *SymmetricKey
	SendChain          *SymmetricKey
	ReceiveChain       *SymmetricKey
	CachedReceiveKeys  map[int]*SymmetricKey
	SendCounter        int
	LastUpdate         int
	ReceiveCounter     int
	prevReceiveCounter int
	initiator          bool
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	// Generate a new DH key pair for the ratchet
	myDHRatchet := GenerateKeyPair()

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:        myDHRatchet,
		PartnerDHRatchet:   nil,
		RootChain:          nil,
		SendChain:          nil,
		ReceiveChain:       nil,
		CachedReceiveKeys:  make(map[int]*SymmetricKey),
		SendCounter:        0,
		LastUpdate:         0,
		ReceiveCounter:     0,
		prevReceiveCounter: 0,
		initiator:          true,
	}

	return &myDHRatchet.PublicKey, nil

}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	// Generate a new DH key pair for the ratchet
	myDHRatchet := GenerateKeyPair()

	// Generate the shared secret
	sharedSecret_Ab := DHCombine(partnerIdentity, &myDHRatchet.PrivateKey)
	sharedSecret_aB := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	sharedSecret_ab := DHCombine(partnerEphemeral, &myDHRatchet.PrivateKey)

	// Combine the shared secrets
	sharedSecret := CombineKeys(sharedSecret_Ab, sharedSecret_aB, sharedSecret_ab)

	// Derive the check key
	checkKey := sharedSecret.DeriveKey(HANDSHAKE_CHECK_LABEL)

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:        myDHRatchet,
		PartnerDHRatchet:   partnerEphemeral,
		RootChain:          sharedSecret,
		SendChain:          nil,
		ReceiveChain:       nil,
		CachedReceiveKeys:  make(map[int]*SymmetricKey),
		SendCounter:        0,
		LastUpdate:         0,
		ReceiveCounter:     0,
		prevReceiveCounter: 0,
		initiator:          false,
	}

	return &myDHRatchet.PublicKey, checkKey, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	// Generate the shared secret
	sharedSecret_Ab := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	sharedSecret_aB := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	sharedSecret_ab := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	// Combine the shared secrets
	sharedSecret := CombineKeys(sharedSecret_Ab, sharedSecret_aB, sharedSecret_ab)

	// Update the root chain to shared secret
	c.Sessions[*partnerIdentity].RootChain = sharedSecret
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral

	// Derive the check key
	checkKey := sharedSecret.DeriveKey(HANDSHAKE_CHECK_LABEL)

	return checkKey, nil

}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	fmt.Println("initiator: ", c.Sessions[*partnerIdentity].initiator)

	if c.Sessions[*partnerIdentity].SendCounter == 0 && c.Sessions[*partnerIdentity].initiator == true {
		// for the very first msg & anyone can send the first msg
		// if the first msg is sent by the initiator, then she doesn't have to ratchet the root chain
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

		// update the last update which is the message counter when root chain was last updated
		c.Sessions[*partnerIdentity].LastUpdate++
		fmt.Println("Initiator sends the first msg")

	} else if c.Sessions[*partnerIdentity].SendCounter == 0 && c.Sessions[*partnerIdentity].initiator == false {
		// but if Bob sends the first msg, then he has to ratchet the root chain first
		newKeyPair := GenerateKeyPair()
		c.Sessions[*partnerIdentity].MyDHRatchet = newKeyPair
		newDHValue := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &newKeyPair.PrivateKey)

		c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain, newDHValue)
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

		// update the last update which is the message counter when root chain was last updated
		c.Sessions[*partnerIdentity].LastUpdate++
		fmt.Println("Responder sends the first msg")

	} else if c.Sessions[*partnerIdentity].ReceiveCounter == c.Sessions[*partnerIdentity].prevReceiveCounter {
		// in case of multiple msg in a row
		// if prev receive counter is equal to current receive counter, then he didn't get a response back aka keep the root chain
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

	} else {
		// create a new root key for a new row of messages
		newKeyPair := GenerateKeyPair()
		c.Sessions[*partnerIdentity].MyDHRatchet = newKeyPair
		newDHValue := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &newKeyPair.PrivateKey)

		c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain, newDHValue)
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)

		// update the last update which is the message counter when root chain was last updated
		c.Sessions[*partnerIdentity].LastUpdate++
	}

	// Increment the send counter.
	c.Sessions[*partnerIdentity].SendCounter++

	IV := NewIV()
	msgKey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		// &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		// &newKeyPair.PublicKey,
		Counter:    c.Sessions[*partnerIdentity].SendCounter,
		LastUpdate: c.Sessions[*partnerIdentity].LastUpdate,
		IV:         IV,
	}

	Ciphertext := msgKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), IV)
	message.Ciphertext = Ciphertext

	// match previous receive counter to current receive counter
	c.Sessions[*partnerIdentity].prevReceiveCounter = c.Sessions[*partnerIdentity].ReceiveCounter

	fmt.Println("Send:  ", plaintext, Ciphertext)

	return message, nil
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. You'll need to implement the code to ratchet, derive keys and decrypt this message.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// Increment the receive counter.
	c.Sessions[*message.Sender].ReceiveCounter++

	//&& message.Counter == c.Sessions[*message.Sender].ReceiveCounter
	if c.Sessions[*message.Sender].ReceiveCounter == 0 && c.Sessions[*message.Sender].SendCounter == 0 {
		// first in-order message to receive
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)

	} else if *message.NextDHRatchet == *c.Sessions[*message.Sender].PartnerDHRatchet {
		// if nextDHRatchet is equal to partnerDHRatchet, then Sender didn't change the root key so I dont have to either
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)

	} else {
		newDHValue := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
		c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newDHValue)
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)

	}

	// decrypt the message
	msgKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
	plaintext, err := msgKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	if err != nil {
		fmt.Println("the error is: ", err)
		return "", err
	}

	//update the partnerDHRatchet to the nextDHRatchet
	c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet

	// zeroize the private key
	//c.Sessions[*message.Sender].MyDHRatchet.PrivateKey.Zeroize()

	fmt.Println("Receive:", plaintext, message.Ciphertext)

	return plaintext, nil

}
