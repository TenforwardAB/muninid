/**
 * This file is licensed under the European Union Public License (EUPL) v1.2.
 * You may only use this work in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed "as is",
 * without any warranty or conditions of any kind.
 *
 * Copyright (c) 2024- Tenforward AB. All rights reserved.
 *
 * Created on 4/23/25 :: 1:22PM BY joyider <andre(-at-)sess.se>
 *
 * This file :: internal/secret/secret.go is part of the MuninID project.
 */

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const prefix = "enc:v1:"

type Store struct {
	key []byte
}

func New(raw string) *Store {
	sum := sha256.Sum256([]byte(raw))
	return &Store{key: sum[:]}
}

func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, prefix)
}

func (s *Store) Encrypt(plaintext string) (string, error) {
	if IsEncrypted(plaintext) {
		return plaintext, nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
	tagStart := len(sealed) - gcm.Overhead()
	return "enc:v1:" + b64(iv) + ":" + b64(sealed[tagStart:]) + ":" + b64(sealed[:tagStart]), nil
}

func (s *Store) Decrypt(value string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 5 || parts[0] != "enc" || parts[1] != "v1" {
		return "", errors.New("invalid encrypted secret format")
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	combined := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, combined, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
