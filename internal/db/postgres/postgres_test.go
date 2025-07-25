package postgres

import "testing"

func TestRebind(t *testing.T) {
	testCases := []struct {
		name  string
		query string
		want  string
	}{
		{
			name:  "no placeholders",
			query: "SELECT * FROM users",
			want:  "SELECT * FROM users",
		},
		{
			name:  "one placeholder",
			query: "SELECT * FROM users WHERE id = ?",
			want:  "SELECT * FROM users WHERE id = $1",
		},
		{
			name:  "multiple placeholders",
			query: "INSERT INTO users (name, email) VALUES (?, ?)",
			want:  "INSERT INTO users (name, email) VALUES ($1, $2)",
		},
		{
			name:  "empty query",
			query: "",
			want:  "",
		},
		{
			name:  "query ending with placeholder",
			query: "DELETE FROM users WHERE id = ?",
			want:  "DELETE FROM users WHERE id = $1",
		},
		{
			name:  "query with question mark literal",
			query: "SELECT '?' FROM users WHERE id = ?",
			want:  "SELECT '?' FROM users WHERE id = $1",
		},
		{
			name:  "query with escaped single quote",
			query: "UPDATE users SET name = 'O''Malley' WHERE id = ?",
			want:  "UPDATE users SET name = 'O''Malley' WHERE id = $1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Rebind(tc.query); got != tc.want {
				t.Errorf("Rebind() = %q, want %q", got, tc.want)
			}
		})
	}
}
