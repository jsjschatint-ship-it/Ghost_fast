package runner

import (
	"context"
	"time"
)

// Limiter 全局速率限制器（令牌桶）
type Limiter struct {
	rate       int           // 每秒生成令牌数
	burst      int           // 桶容量
	tokens     chan struct{} // 令牌通道
	lastUpdate time.Time
}

// NewLimiter 创建速率限制器
func NewLimiter(rate, burst int) *Limiter {
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = rate
	}
	l := &Limiter{
		rate:   rate,
		burst:  burst,
		tokens: make(chan struct{}, burst),
	}
	// 初始填充桶
	for i := 0; i < burst; i++ {
		l.tokens <- struct{}{}
	}
	go l.refill()
	return l
}

// refill 定期补充令牌
func (l *Limiter) refill() {
	ticker := time.NewTicker(time.Second / time.Duration(l.rate))
	defer ticker.Stop()
	for range ticker.C {
		select {
		case l.tokens <- struct{}{}:
		default: // 桶满，丢弃
		}
	}
}

// Wait 等待一个令牌
func (l *Limiter) Wait(ctx context.Context) error {
	select {
	case <-l.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryTry 尝试获取令牌（非阻塞）
func (l *Limiter) TryTake() bool {
	select {
	case <-l.tokens:
		return true
	default:
		return false
	}
}
