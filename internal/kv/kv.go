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
 * This file :: internal/kv/kv.go is part of the MuninID project.
 */

// Package kv is a thin valkey/redis wrapper for muninid's ephemeral, TTL-native
// state (OAuth token sessions, login interactions, rate-limit counters). Durable
// records (clients, keys, policies, audit, consent) stay in postgres.
package kv

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNil is returned when a key does not exist.
var ErrNil = errors.New("kv: key not found")

type Client struct {
	rdb *redis.Client
}

func New(url string) (*Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Client{rdb: redis.NewClient(opt)}, nil
}

func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// Get returns the raw value for key, or ErrNil if it does not exist.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNil
	}
	return b, err
}

// Set stores value at key. A ttl <= 0 means no expiry.
func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

func (c *Client) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

// PTTL returns the remaining time-to-live for key. A negative duration means the
// key has no expiry (-1) or does not exist (-2), mirroring redis semantics.
func (c *Client) PTTL(ctx context.Context, key string) (time.Duration, error) {
	return c.rdb.PTTL(ctx, key).Result()
}

// SAdd adds members to a set keyed by key and refreshes its ttl.
func (c *Client) SAdd(ctx context.Context, key string, ttl time.Duration, members ...string) error {
	pipe := c.rdb.TxPipeline()
	args := make([]any, len(members))
	for i, m := range members {
		args[i] = m
	}
	pipe.SAdd(ctx, key, args...)
	if ttl > 0 {
		pipe.Expire(ctx, key, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (c *Client) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.rdb.SMembers(ctx, key).Result()
}

// IncrTTL increments a counter and, on first creation, sets its expiry window.
// Returns the new counter value.
func (c *Client) IncrTTL(ctx context.Context, key string, window time.Duration) (int64, error) {
	n, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 && window > 0 {
		if err := c.rdb.Expire(ctx, key, window).Err(); err != nil {
			return n, err
		}
	}
	return n, nil
}
