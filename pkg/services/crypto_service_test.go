package services

import "testing"

func TestCryptoService_EncryptDecryptRoundtrip(t *testing.T) {
	cs, err := NewCryptoService("01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "my-api-key-12345"
	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if plaintext == ciphertext {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != plaintext {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestCryptoService_WrongKey(t *testing.T) {
	cs1, _ := NewCryptoService("01234567890123456789012345678901")
	cs2, _ := NewCryptoService("98765432109876543210987654321098")

	ciphertext, err := cs1.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}

	_, err = cs2.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestCryptoService_InvalidKeySize(t *testing.T) {
	_, err := NewCryptoService("short")
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestCryptoService_EmptyInput(t *testing.T) {
	cs, _ := NewCryptoService("01234567890123456789012345678901")

	ciphertext, err := cs.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != "" {
		t.Errorf("expected empty string, got %s", decrypted)
	}
}
