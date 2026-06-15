package database

import (
	"context"
	"net"
	"strconv"

	goredis "github.com/redis/go-redis/v9"
)

// redisBackend 抽象 Redis 只读信息与危险清库操作,便于 mock 测业务。
type redisBackend interface {
	info(ctx context.Context) (string, error)
	dbSize(ctx context.Context) (int64, error)
	flushDB(ctx context.Context) error
	close() error
}

// redisConnector 按当前设置打开 Redis 连接。
type redisConnector func(ctx context.Context, s Settings) (redisBackend, error)

// goRedisBackend 用 go-redis 实现 redisBackend。
type goRedisBackend struct{ c *goredis.Client }

func (b *goRedisBackend) info(ctx context.Context) (string, error) {
	return b.c.Info(ctx).Result()
}

func (b *goRedisBackend) dbSize(ctx context.Context) (int64, error) {
	return b.c.DBSize(ctx).Result()
}

func (b *goRedisBackend) flushDB(ctx context.Context) error {
	return b.c.FlushDB(ctx).Err()
}

func (b *goRedisBackend) close() error { return b.c.Close() }

// realRedisConnector 用设置建 go-redis 客户端并 ping。
func realRedisConnector(ctx context.Context, s Settings) (redisBackend, error) {
	c := goredis.NewClient(&goredis.Options{
		Addr:     net.JoinHostPort(s.RedisHost, strconv.Itoa(s.RedisPort)),
		Password: s.RedisPassword,
	})
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, err
	}
	return &goRedisBackend{c: c}, nil
}
