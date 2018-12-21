package cli

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/immutability-io/nkey/util"
	nats "github.com/nats-io/go-nats"
	"github.com/nats-io/jwt"
)

// CryptoHelper is a function that encrypts or decrypts.
type CryptoHelper func([]byte) ([]byte, error)

func basicUserJWTHandler(accountPath, userPath string) (string, error) {
	cli, err := api.NewClient(nil)
	if err != nil {
		return "", err
	}
	subjectSecret, err := cli.Logical().Read(userPath)
	if err != nil {
		return "", err
	}
	subject := subjectSecret.Data["public_key"].(string)
	uc := jwt.NewUserClaims(subject)
	data := make(map[string]interface{})
	data["claims"] = uc.String()
	data["type"] = "user"

	claimsPath := fmt.Sprintf("%s/sign-claim", accountPath)

	secret, err := cli.Logical().Write(claimsPath, data)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("problem writing claim")
	}
	return secret.Data["token"].(string), nil
}

func basicSignatureHandler(nonce []byte, path string) ([]byte, error) {
	cli, err := api.NewClient(nil)
	data := make(map[string]interface{})
	data["payload"] = string(nonce)

	signingPath := fmt.Sprintf("%s/sign", path)

	secret, err := cli.Logical().Write(signingPath, data)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("problem signing nonce")
	}
	signature := secret.Data["signature"].(string)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	return signatureBytes, nil
}

// VaultCredentials is a convenience function that takes a filename
// for a user's JWT and a filename for the user's private Nkey seed.
func VaultCredentials(accountPath, userPath string) nats.Option {
	userCB := func() (string, error) {
		return basicUserJWTHandler(accountPath, userPath)
	}
	sigCB := func(nonce []byte) ([]byte, error) {
		return basicSignatureHandler(nonce, userPath)
	}
	return nats.UserJWT(userCB, sigCB)
}

// VaultDecryptor is a function that can decrypt based on a vault identity
func VaultDecryptor(path string) CryptoHelper {
	return func(ciphertext []byte) ([]byte, error) {
		cli, err := api.NewClient(nil)
		if err != nil {
			return nil, err
		}
		data := make(map[string]interface{})
		data["cyphertext"] = base64.StdEncoding.EncodeToString(ciphertext)

		decryptPath := fmt.Sprintf("%s/decrypt", path)

		secret, err := cli.Logical().Write(decryptPath, data)
		if err != nil {
			return nil, err
		}
		if secret == nil {
			return nil, fmt.Errorf("problem decrypting")
		}
		plaintext, err := base64.StdEncoding.DecodeString(secret.Data["plaintext"].(string))
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
}

// VaultEncryptor is a function that can encrypt based on a vault identity
func VaultEncryptor(path string) CryptoHelper {
	return func(plaintext []byte) ([]byte, error) {
		cli, err := api.NewClient(nil)
		if err != nil {
			return nil, err
		}
		data := make(map[string]interface{})
		data["plaintext"] = base64.StdEncoding.EncodeToString(plaintext)

		encryptPath := fmt.Sprintf("%s/encrypt", path)

		secret, err := cli.Logical().Write(encryptPath, data)
		if err != nil {
			return nil, err
		}
		if secret == nil {
			return nil, fmt.Errorf("problem encrypting")
		}
		cyphertext, err := base64.StdEncoding.DecodeString(secret.Data["cyphertext"].(string))
		if err != nil {
			return nil, err
		}
		return cyphertext, nil
	}
}

// BTCEncryptor is a function that can encrypt based on a public key
func BTCEncryptor(publicKey string) CryptoHelper {
	return func(plaintext []byte) ([]byte, error) {
		ciphertext, err := util.Encrypt(publicKey, base64.StdEncoding.EncodeToString(plaintext))
		if err != nil {
			return nil, err
		}
		cyphertext, err := base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			return nil, err
		}
		return cyphertext, nil
	}
}

// BTCDecryptor is a function that can decrypt based on a private key
func BTCDecryptor(privateKey string) CryptoHelper {
	return func(ciphertext []byte) ([]byte, error) {
		plaintext, err := util.Decrypt(privateKey, base64.StdEncoding.EncodeToString(ciphertext))
		if err != nil {
			return nil, err
		}
		playntext, err := base64.StdEncoding.DecodeString(plaintext)
		if err != nil {
			return nil, err
		}
		return playntext, nil
	}
}

// FromCredsDecryptor is a function that can decrypt based on a creds file1
func FromCredsDecryptor(path string) CryptoHelper {
	return func(ciphertext []byte) ([]byte, error) {
		_, _, privateKey, err := util.CredsFromNkeyFile(path)
		if err != nil {
			return nil, err
		}
		if privateKey == util.Empty {
			return nil, fmt.Errorf("no private key available")
		}
		plaintext, err := util.Decrypt(privateKey, base64.StdEncoding.EncodeToString(ciphertext))
		if err != nil {
			return nil, err
		}
		playntext, err := base64.StdEncoding.DecodeString(plaintext)
		if err != nil {
			return nil, err
		}
		return playntext, nil
	}
}
