package kit

import "encoding/base64"

func AESTextEnc(source string, pass []byte) ([]byte, error) {
	dk, salt, err := deriveKey(pass, nil, 32)
	if err != nil {
		return nil, err
	}
	block, err := aescipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := aesgcm(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, salt, []byte(source), nil)
	// Append the salt to the end of file
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func AESTextDec(source string, pass []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(source)
	if err != nil {
		return nil, err
	}
	salt := ciphertext[len(ciphertext)-12:]
	dk, _, err := deriveKey(pass, salt, 32)
	if err != nil {
		return nil, err
	}
	block, err := aescipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := aesgcm(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, salt, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
