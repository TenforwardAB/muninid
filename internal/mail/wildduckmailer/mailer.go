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
 * This file :: internal/mail/wildduckmailer/mailer.go is part of the MuninID project.
 */

// Package wildduckmailer implements authn.Mailer by submitting messages through
// WildDuck (POST /users/:id/submit) as a configured system sender. Swapping to
// a plain SMTP relay later is a matter of providing a different authn.Mailer.
package wildduckmailer

import (
	"context"
	"errors"
	"fmt"
	"html"

	wd "github.com/tenforwardab/wildduck-gosdk"
)

// Mailer sends mail as the WildDuck user identified by SenderUserID, using
// FromAddress/FromName as the visible From header.
type Mailer struct {
	c           *wd.Client
	senderID    string
	fromAddress string
	fromName    string
}

func New(c *wd.Client, senderUserID, fromAddress, fromName string) *Mailer {
	return &Mailer{c: c, senderID: senderUserID, fromAddress: fromAddress, fromName: fromName}
}

// SendPasswordReset mails a single-use reset link.
func (m *Mailer) SendPasswordReset(ctx context.Context, to, displayName, link string) error {
	if m.senderID == "" {
		return errors.New("reset sender not configured (RESET_SENDER_USER_ID)")
	}
	name := displayName
	if name == "" {
		name = to
	}
	subject := "Reset your password"
	text := fmt.Sprintf(
		"Hi,\n\nWe received a request to reset the password for your account.\n\n"+
			"Open the link below to choose a new password. It expires shortly and can only be used once:\n\n%s\n\n"+
			"If you didn't request this, you can safely ignore this email — your password stays unchanged.\n",
		link)
	body := html.EscapeString(link)
	htmlBody := fmt.Sprintf(
		`<p>Hi,</p><p>We received a request to reset the password for your account.</p>`+
			`<p>Choose a new password using the button below. The link expires shortly and can only be used once.</p>`+
			`<p><a href="%s" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;`+
			`text-decoration:none;border-radius:8px;font-weight:600">Reset password</a></p>`+
			`<p style="color:#64748b;font-size:13px">Or paste this link into your browser:<br>%s</p>`+
			`<p style="color:#64748b;font-size:13px">If you didn't request this, you can ignore this email — `+
			`your password stays unchanged.</p>`,
		body, body)

	payload := wd.M{
		"from":    wd.M{"name": m.fromName, "address": m.fromAddress},
		"to":      []wd.M{{"name": name, "address": to}},
		"subject": subject,
		"text":    text,
		"html":    htmlBody,
	}
	res, err := m.c.Submission.Submit(ctx, m.senderID, payload)
	if err != nil {
		return err
	}
	if res["success"] != true {
		return errors.New("wildduck submission failed")
	}
	return nil
}
