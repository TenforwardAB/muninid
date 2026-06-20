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
 * This file :: internal/fositestore/hasher.go is part of the MuninID project.
 */

package fositestore

import (
	"context"
	"crypto/subtle"

	"github.com/ory/fosite"
	"github.com/pkg/errors"

	"github.com/tenforwardab/muninid/internal/secret"
)

type EncryptedSecretHasher struct {
	Secrets *secret.Store
}

func (h EncryptedSecretHasher) Compare(_ context.Context, hash, data []byte) error {
	expected := string(hash)
	if h.Secrets != nil {
		plain, err := h.Secrets.Decrypt(expected)
		if err != nil {
			return err
		}
		expected = plain
	}
	if subtle.ConstantTimeCompare([]byte(expected), data) != 1 {
		return errors.WithStack(fosite.ErrInvalidClient)
	}
	return nil
}

func (h EncryptedSecretHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	if h.Secrets == nil {
		return append([]byte(nil), data...), nil
	}
	encrypted, err := h.Secrets.Encrypt(string(data))
	if err != nil {
		return nil, err
	}
	return []byte(encrypted), nil
}

var _ fosite.Hasher = (*EncryptedSecretHasher)(nil)
