package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/wgpsec/ENScan/pkg/models"
)

// DBPath SQLite 数据库路径
const DBPath = "data/sessions.db"

// Session 会话记录
type Session struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Query      string    `json:"query"`
	Targets    string    `json:"targets"`
	AssetCount int       `json:"asset_count"`
	Meta       string    `json:"meta"`
	Notes      string    `json:"notes"` // 用户自定义备注（red-team prep 之类）
	CreatedAt  time.Time `json:"created_at"`
}

// ensureDir 确保目录存在
func ensureDir() error {
	dir := filepath.Dir(DBPath)
	return os.MkdirAll(dir, 0700)
}

// openDB 打开数据库连接
func openDB() (*sql.DB, error) {
	if err := ensureDir(); err != nil {
		return nil, fmt.Errorf("ensure dir: %w", err)
	}
	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return db, nil
}

// InitDB 初始化数据库表（含老库 schema 迁移）。
//
// 兼容 Python 版留下的旧库（assets 表 schema 不一定有 created_at 等列）。
// 策略：CREATE IF NOT EXISTS 建新表 + 检测每个期望列是否存在 → 不存在就 ALTER ADD。
func InitDB() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	sqlStmt := `
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    query       TEXT,
    targets     TEXT,
    asset_count INTEGER DEFAULT 0,
    meta        TEXT,
    created_at  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assets_session_id ON assets(session_id);
`
	if _, err = db.Exec(sqlStmt); err != nil {
		return fmt.Errorf("exec schema: %w", err)
	}
	// 兼容老库：补齐缺失列（Python 版 schema 可能没有 created_at / meta / query 等）。
	type colSpec struct{ name, ddl string }
	migrations := map[string][]colSpec{
		"sessions": {
			{"query", "ALTER TABLE sessions ADD COLUMN query TEXT"},
			{"targets", "ALTER TABLE sessions ADD COLUMN targets TEXT"},
			{"asset_count", "ALTER TABLE sessions ADD COLUMN asset_count INTEGER DEFAULT 0"},
			{"meta", "ALTER TABLE sessions ADD COLUMN meta TEXT"},
			{"notes", "ALTER TABLE sessions ADD COLUMN notes TEXT NOT NULL DEFAULT ''"},
			{"created_at", "ALTER TABLE sessions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"},
		},
		"assets": {
			{"data", "ALTER TABLE assets ADD COLUMN data TEXT NOT NULL DEFAULT ''"},
			{"created_at", "ALTER TABLE assets ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"},
			// is_raw=1 表示采集原始堆（dedup 前），=0 是当前视图（默认 smart-dedup 后）
			{"is_raw", "ALTER TABLE assets ADD COLUMN is_raw INTEGER NOT NULL DEFAULT 0"},
		},
	}
	for table, specs := range migrations {
		existing, err := tableColumns(db, table)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", table, err)
		}
		for _, spec := range specs {
			if _, ok := existing[spec.name]; ok {
				continue
			}
			if _, err := db.Exec(spec.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", table, spec.name, err)
			}
		}
	}
	return nil
}

// tableColumns 列出某个表已有的列名（小写化）。
func tableColumns(db *sql.DB, table string) (map[string]struct{}, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{}, 16)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = struct{}{}
	}
	return out, nil
}

// SaveSession 保存会话与资产快照（仅 deduped 视图，向后兼容老调用）。
func SaveSession(name, query, targets string, assets []*models.Asset, meta map[string]any) (int, error) {
	return SaveSessionWithRaw(name, query, targets, assets, nil, meta)
}

// SaveSessionWithRaw 同时保存 deduped 视图（is_raw=0）和原始堆（is_raw=1）。
// 当 raw == nil 或 len(raw) == 0 时，等价于 SaveSession。
// 注意 asset_count 只记录 deduped 视图的条数，与历史口径一致。
func SaveSessionWithRaw(name, query, targets string, assets, raw []*models.Asset, meta map[string]any) (int, error) {
	db, err := openDB()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	metaBytes, _ := json.Marshal(meta)
	metaStr := string(metaBytes)
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(
		`INSERT INTO sessions (name, query, targets, asset_count, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		name, query, targets, len(assets), metaStr, now,
	)
	if err != nil {
		return 0, fmt.Errorf("insert session: %w", err)
	}
	sessionID, _ := res.LastInsertId()
	stmt, err := tx.Prepare(`INSERT INTO assets (session_id, data, created_at, is_raw) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()
	insert := func(list []*models.Asset, isRaw int) {
		for _, a := range list {
			data, err := json.Marshal(a)
			if err != nil {
				continue
			}
			_, _ = stmt.Exec(sessionID, string(data), now, isRaw)
		}
	}
	insert(assets, 0)
	if len(raw) > 0 {
		insert(raw, 1)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return int(sessionID), nil
}

// ListSessions 列出所有会话
func ListSessions() ([]Session, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, name, query, targets, asset_count, meta, COALESCE(notes,''), created_at FROM sessions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()
	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.Name, &s.Query, &s.Targets, &s.AssetCount, &s.Meta, &s.Notes, &s.CreatedAt); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// UpdateSessionNotes 更新某个会话的备注。
func UpdateSessionNotes(sessionID int, notes string) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE sessions SET notes = ? WHERE id = ?`, notes, sessionID)
	if err != nil {
		return fmt.Errorf("update notes: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %d not found", sessionID)
	}
	return nil
}

// LoadSession 加载会话的 deduped 视图（is_raw=0）。
// 兼容老库：当一条 raw 记录都没有时（is_raw 全为 0/NULL），与原行为完全一致。
func LoadSession(sessionID int) ([]*models.Asset, error) {
	return loadSessionFiltered(sessionID, 0)
}

// LoadSessionRaw 加载会话的原始堆（is_raw=1）。
// 若没有任何 raw 记录（老库 / 旧会话），则回退到 deduped 视图，调用方可凭返回行数判断。
func LoadSessionRaw(sessionID int) ([]*models.Asset, error) {
	raw, err := loadSessionFiltered(sessionID, 1)
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		return raw, nil
	}
	// 老会话没存 raw，回退到 deduped
	return LoadSession(sessionID)
}

func loadSessionFiltered(sessionID, isRaw int) ([]*models.Asset, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT data FROM assets WHERE session_id = ? AND is_raw = ? ORDER BY id`, sessionID, isRaw)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	defer rows.Close()
	var assets []*models.Asset
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var a models.Asset
		if err := json.Unmarshal([]byte(data), &a); err != nil {
			continue
		}
		assets = append(assets, &a)
	}
	return assets, nil
}

// DeleteSession 删除会话（级联删除资产）
func DeleteSession(sessionID int) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
