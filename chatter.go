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
		LastUpdate:         -1,
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

func (c *Chatter) CreateNewChain(partnerIdentity *PublicKey) *SymmetricKey {

	// generate new DH key pair and create new root chain
	c.Sessions[*partnerIdentity].MyDHRatchet = GenerateKeyPair()
	newDHValue := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL), newDHValue)
	fmt.Println("PARTNER DH", c.Sessions[*partnerIdentity].PartnerDHRatchet)
	fmt.Println("NEW ROOT", c.Sessions[*partnerIdentity].RootChain)

	// create new send chain
	NewSendChain := c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
	fmt.Println("Send Chain", NewSendChain)

	// create an input for next root key
	c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
	fmt.Println("Next Root Chain", c.Sessions[*partnerIdentity].RootChain)

	return NewSendChain
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}
	fmt.Println(".")
	fmt.Println("Starting Root chain: ", c.Sessions[*partnerIdentity].RootChain)
	fmt.Println("My Starting DH: ", c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey)

	c.Sessions[*partnerIdentity].SendCounter++

	var NewSendChain *SymmetricKey
	if c.Sessions[*partnerIdentity].LastUpdate == -1 {

		// Case for Alice's first message: She uses the initial root chain
		NewSendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter
		fmt.Println("Ratcheted Root Chain", c.Sessions[*partnerIdentity].RootChain)

	} else if c.Sessions[*partnerIdentity].LastUpdate == 0 {

		// Case for Bob's first message: Bob creates a new root chain even if he sends the very first message
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
		fmt.Println("Ratcheted Root Chain", c.Sessions[*partnerIdentity].RootChain)
		NewSendChain = c.CreateNewChain(partnerIdentity)
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter

	} else if c.Sessions[*partnerIdentity].prevReceiveCounter == c.Sessions[*partnerIdentity].ReceiveCounter {

		// Case for a msg in the middle of mulitple messages in a row: Only send chain is ratcheted
		NewSendChain = c.Sessions[*partnerIdentity].SendChain

	} else {

		// Case for first messages after receiving a response: Create a new root chain
		NewSendChain = c.CreateNewChain(partnerIdentity)
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter
		c.Sessions[*partnerIdentity].prevReceiveCounter = c.Sessions[*partnerIdentity].ReceiveCounter

	}

	c.Sessions[*partnerIdentity].SendChain = NewSendChain.DeriveKey(CHAIN_LABEL)
	fmt.Println("Send Chain", NewSendChain)
	fmt.Println("Next Send Chain will be ", c.Sessions[*partnerIdentity].SendChain)

	// encrypt message
	IV := NewIV()
	msgKey := NewSendChain.DeriveKey(KEY_LABEL)

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		Counter:       c.Sessions[*partnerIdentity].SendCounter,
		LastUpdate:    c.Sessions[*partnerIdentity].LastUpdate,
		IV:            IV,
	}

	Ciphertext := msgKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), IV)
	message.Ciphertext = Ciphertext
	fmt.Println("counter; ", message.Counter, "sent by ", c.Sessions[*partnerIdentity].initiator, "msgKey: ", msgKey)
	fmt.Println("My Next DH: ", c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey)

	// fmt.Println("Send Chain:", NewSendChain)

	return message, nil

}

func (c *Chatter) UpdateToNewChain(message *Message) *SymmetricKey {

	// compute new DH value and create new root chain
	newDHValue := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
	c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL), newDHValue)
	fmt.Println("PARTNER DH", message.NextDHRatchet)
	fmt.Println("ROOT Chain", c.Sessions[*message.Sender].RootChain)

	// create new receive chain
	NewReceiveChain := c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
	fmt.Println("Receive Chain", NewReceiveChain)

	// create an input for next root key
	c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)

	c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
	c.Sessions[*message.Sender].MyDHRatchet.PrivateKey.Zeroize()

	return NewReceiveChain
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}
	// debug
	fmt.Println(".")
	fmt.Println("Message ", message.Counter, "received by ", c.Sessions[*message.Sender].initiator)
	fmt.Println("Starting Root Chain", c.Sessions[*message.Sender].RootChain)
	fmt.Println("MY Starting DH: ", c.Sessions[*message.Sender].MyDHRatchet.PublicKey)

	c.Sessions[*message.Sender].ReceiveCounter++

	var NewReceiveChain *SymmetricKey
	if c.Sessions[*message.Sender].LastUpdate == 0 {
		// Case: Bob received the very first message in the conversation from Alice: Alice used the initial root chain
		NewReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)
		c.Sessions[*message.Sender].LastUpdate = message.LastUpdate
		c.Sessions[*message.Sender].ReceiveChain = NewReceiveChain.DeriveKey(CHAIN_LABEL)
		fmt.Println("Ratcheted Root Chain", c.Sessions[*message.Sender].RootChain)
		fmt.Println("Bob received Alice's first message")

	} else if c.Sessions[*message.Sender].LastUpdate == -1 {
		// Case: Alice received the very first message in the conversation from Bob: Bob had to get a new root chain regardless so Alice should update her root chain too
		NewReceiveChain = c.UpdateToNewChain(message)
		c.Sessions[*message.Sender].LastUpdate = message.LastUpdate
		c.Sessions[*message.Sender].ReceiveChain = NewReceiveChain.DeriveKey(CHAIN_LABEL)
		fmt.Println("Next Root Chain", c.Sessions[*message.Sender].RootChain)

		fmt.Println("Alice received Bob's first message")

	} else if message.Counter > c.Sessions[*message.Sender].ReceiveCounter {

		fmt.Println("LastUpdate: ", message.LastUpdate)

		// handle early messages
		for i := c.Sessions[*message.Sender].ReceiveCounter; i <= int(message.Counter); i++ {

			var prevChain *SymmetricKey
			if i == message.LastUpdate {
				// Root chain is ratcheted for this message; It's either the first msg from Bob or first msg after a response
				// Exception for the first message from Alice
				fmt.Println(".")
				fmt.Println("Ratcheting root chain for message ", i, "...")

				if i == 1 && c.Sessions[*message.Sender].initiator == true {
					// Case: Last Update was for M1 and Alice is the receiver; She has to ratchet bc Bob would've ratcheted for his first message
					prevChain = c.UpdateToNewChain(message)
					fmt.Println("Next ROOTCHAIN", c.Sessions[*message.Sender].RootChain)

					fmt.Println("Alice is caching Bob's first message which is also when root was last updated...")

				} else if i == 1 && c.Sessions[*message.Sender].initiator == false {
					// Case: Last Update was for M1 and Bob is the receiver; Alice used the initial root chain when she sent her first message
					//actually, keep the initial root and derive receive chain from that
					// derive chain_key
					prevChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
					c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)
					fmt.Println("Just kidding, Alice didn't ratchet the root chain. Bob is just caching Alice's first message which is also when root was last updated...")

				} else {
					// Case: Last Update was for M2 or later; This is the first of new set of messages received;
					// Regardless of who, the root chain was updated before sending so the same should be done when receving
					prevChain = c.UpdateToNewChain(message)
					fmt.Println("Ratcheting first then caching message ", i, "...")

				}

			} else {
				// Root chain was not updated for this message
				fmt.Println(".")
				fmt.Println("Using the same root chain for message ", i, "...")

				if i == 1 && c.Sessions[*message.Sender].initiator == true {
					// Case: The first message from Bob is not the one with Last Update; But Alice knows that Bob ratcheted the root chain for it
					prevChain = c.UpdateToNewChain(message)
					fmt.Println("Alice is caching Bob's first message...")

				} else if i == 1 && c.Sessions[*message.Sender].initiator == false {
					// Case: The first message from Alice is not the one with Last Update; And Bob knows that Alice used the initial root chain for it

					//Bob computes for the first msg which is not Last update aka there's new DH ratchet in the future.
					// actually, keep the initial root and derive receive chain from that
					// Bob should use receive chain from root chain if it's the first message
					prevChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
					c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)
					fmt.Println("Bob is caching Alice's first message...")

				} else {
					// Case: The message does not have a new DH ratchet aka it's M2 or greater in a set of messages sent in a row

					prevChain = c.Sessions[*message.Sender].ReceiveChain
					fmt.Println("Just caching message ", i, "...")
				}

			}

			c.Sessions[*message.Sender].ReceiveChain = prevChain.DeriveKey(CHAIN_LABEL)
			fmt.Println("Receive Chain", prevChain)
			fmt.Println("Next Receive Chain", c.Sessions[*message.Sender].ReceiveChain)
			prevMsgKey := prevChain.DeriveKey(KEY_LABEL)
			c.Sessions[*message.Sender].CachedReceiveKeys[i] = prevMsgKey
			fmt.Println("Cached message key", prevMsgKey, "for message ", i, "!")
			// fmt.Println("Receive Chain:", prevChain)

		}

	} else if message.NextDHRatchet == c.Sessions[*message.Sender].PartnerDHRatchet {

		// Case: received one of multiple messages in a row: Only ratchet the receive key
		NewReceiveChain = c.Sessions[*message.Sender].ReceiveChain
		c.Sessions[*message.Sender].ReceiveChain = NewReceiveChain.DeriveKey(CHAIN_LABEL)
		fmt.Println("received one of multiple messages in a row")

	} else {

		// Case: reveived a new message after sending one: Get a new root chain
		NewReceiveChain = c.UpdateToNewChain(message)
		c.Sessions[*message.Sender].LastUpdate = message.LastUpdate
		c.Sessions[*message.Sender].ReceiveChain = NewReceiveChain.DeriveKey(CHAIN_LABEL)
		fmt.Println("reveived a new message after sending one")

	}

	// decrypt message
	var msgKey *SymmetricKey
	if c.Sessions[*message.Sender].CachedReceiveKeys[message.Counter] != nil {

		msgKey = c.Sessions[*message.Sender].CachedReceiveKeys[message.Counter]
		fmt.Println("Found cached message key for message ", message.Counter, ": ", msgKey, "!")
	} else {
		fmt.Println("No cached message key for message ", message.Counter, "!")
		msgKey = NewReceiveChain.DeriveKey(KEY_LABEL)
	}

	plaintext, err := msgKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	if err != nil {
		return "", err
	}

	return plaintext, nil

}
