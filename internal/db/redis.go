package db

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
}

func NewRedisClient(addr, password string, db int) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return &RedisClient{client: client}, nil
}

func (rc *RedisClient) IncrementLoginFailures(ctx context.Context, ip string) (int64, error) {
	key := fmt.Sprintf("login_failures:%s", ip)
	count, err := rc.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set expiration of 1 hour if not already set
	rc.client.Expire(ctx, key, time.Hour)
	return count, nil
}

func (rc *RedisClient) GetLoginFailures(ctx context.Context, ip string) (int64, error) {
	key := fmt.Sprintf("login_failures:%s", ip)
	count, err := rc.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

func (rc *RedisClient) ResetLoginFailures(ctx context.Context, ip string) error {
	key := fmt.Sprintf("login_failures:%s", ip)
	return rc.client.Del(ctx, key).Err()
}

func (rc *RedisClient) Close() error {
	return rc.client.Close()
}
