from pathlib import Path
import sqlite3

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = (PROJECT_ROOT / "data" / "app.db").resolve()

def main():
    (PROJECT_ROOT / "data").mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(DB_PATH)) as conn:
        cur = conn.cursor()

        # Create tables
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            day TEXT,
            amount INTEGER
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            name TEXT,
            email TEXT
        );
        """)

        # Seed minimal demo data (only if empty)
        cur.execute("SELECT COUNT(*) FROM sales;")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO sales (day, amount) VALUES (?, ?);",
                [
                    ("2026-01-01", 120),
                    ("2026-01-02", 90),
                    ("2026-01-03", 150),
                    ("2026-01-04", 200),
                ],
            )

        cur.execute("SELECT COUNT(*) FROM users;")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO users (name, email) VALUES (?, ?);",
                [
                    ("Alice", "alice@example.com"),
                    ("Bob", "bob@example.com"),
                ],
            )

        conn.commit()

    print(f"✅ Demo DB initialized at: {DB_PATH}")

if __name__ == "__main__":
    main()
