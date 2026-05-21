.PHONY: build run clean lint fmt deps test

# 默认目标
all: build

# 构建二进制
build:
	@echo "Building Ghost..."
	@mkdir -p bin
	@go build -o bin/Ghost ./cmd/enscan

# 运行（需要 config.yaml）
run: build
	@./bin/Ghost -t example.com

# 安装依赖
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

# 格式化代码
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# 代码检查
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# 测试
test:
	@echo "Running tests..."
	@go test -v ./...

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf bin/

# 跨平台构建
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p bin
	@GOOS=linux GOARCH=amd64 go build -o bin/Ghost-linux-amd64 ./cmd/enscan
	@GOOS=windows GOARCH=amd64 go build -o bin/Ghost-windows-amd64.exe ./cmd/enscan
	@GOOS=darwin GOARCH=amd64 go build -o bin/Ghost-darwin-amd64 ./cmd/enscan

# 生成示例配置
config:
	@echo "Generating example config..."
	@cp config.yaml.example config.yaml.example.bak 2>/dev/null || true
	@cat > config.yaml.example << 'EOF'
# Ghost Go 配置示例
runner:
  enabled:
    - fofa
    - secret_scan
    - pii_scan
    - cloud_bucket
    - source_map_leak
    - netdisk_search
    - employee_dork
    - app_market_search
    - ci_secret_search
    - ipv6_pii_scan
    - company_structure_api
  max_concurrency: 10
  timeout: 30
  proxy: ""
  user_agent: "Ghost-Go/1.0"

engines:
  fofa:
    enabled: true
    key: ""
    size: 100
  hunter:
    enabled: false
    key: ""
    size: 100
  quake:
    enabled: false
    key: ""
    size: 100
  shodan:
    enabled: false
    key: ""
    size: 100
  zoomeye:
    enabled: false
    key: ""
    size: 100
  zerozone:
    enabled: false
    key: ""
    size: 100

sources:
  secret_scan:
    max_assets: 500
  pii_scan:
    max_assets: 500
  cloud_bucket:
    max_candidates: 800
  source_map_leak:
    max_js: 200
  netdisk_search:
    engine: "duckduckgo"
    max_per_dork: 15
    max_dorks: 60
  employee_dork:
    engine: "duckduckgo"
    max_per_dork: 15
    max_dorks: 60
  app_market_search:
    engine: "duckduckgo"
    max_per_dork: 10
    max_dorks: 50
  ci_secret_search:
    engine: "duckduckgo"
    max_per_dork: 10
    max_dorks: 80
  ipv6_pii_scan:
    max_assets: 500
  company_structure_api:
    enscan_endpoint: "http://localhost:8080/api"
    type: "aqc,tyc"
    field: "icp,app,wechat"
    invest: 100
EOF

# 帮助
help:
	@echo "Available targets:"
	@echo "  build      - Build Ghost binary"
	@echo "  run        - Build and run with example target"
	@echo "  deps       - Install dependencies"
	@echo "  fmt        - Format code"
	@echo "  lint       - Run linter"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  build-all  - Build for Linux/Windows/macOS"
	@echo "  config     - Generate example config.yaml"
	@echo "  help       - Show this help"
