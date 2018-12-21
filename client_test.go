package cli

import (
	"testing"
)

var UserEncryptionPublicKey = "04d556a11393f90592c6c4933f2ce0bb4ea015d3f4ce429901e9112f7471cae1a2ebe80c549a97f64cd2cf995fbe751dc59247c73b26e8fd4572d026266efce4ca"

func Test_FileCrypto(t *testing.T) {

	decrypt := FromCredsDecryptor("test.creds")
	encrypt := BTCEncryptor(UserEncryptionPublicKey)
	plaintext := "foobar"
	plaintextBytes := []byte(plaintext)
	ciphertextBytes, err := encrypt(plaintextBytes)
	if err != nil {
		t.Fatalf("Failed encrypt: %s", err)
	}
	decryptedBytes, err := decrypt(ciphertextBytes)
	if err != nil {
		t.Fatalf("Failed decrypt: %s", err)
	}
	decrypted := string(decryptedBytes)
	if decrypted != plaintext {
		t.Fatalf("Failed decrypt. Expected %s; Got %s", plaintext, decrypted)
	}
}
