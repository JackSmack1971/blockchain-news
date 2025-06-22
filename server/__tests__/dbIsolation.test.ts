import { describe, it, beforeEach, afterAll, expect } from 'vitest';
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
const { resetDatabase, withTransaction, pool, closePool } = await import('../db');

describe('database transaction isolation', () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await closePool();
  });

  it('rolls back failed transaction', async () => {
    await expect(
      withTransaction(async client => {
        await client.query(
          "INSERT INTO users (id, email, password_hash, username) VALUES ('00000000-0000-0000-0000-000000000001','a@a.com','hash','alice')"
        );
        throw new Error('fail');
      })
    ).rejects.toThrow();
    const res = await pool.query('SELECT count(*)::int FROM users');
    expect(Number(res.rows[0].count)).toBe(0);
  });

  it('commits successful transaction', async () => {
    await withTransaction(async client => {
      await client.query(
        "INSERT INTO users (id, email, password_hash, username) VALUES ('00000000-0000-0000-0000-000000000002','b@b.com','hash','bob')"
      );
    });
    const res = await pool.query('SELECT count(*)::int FROM users');
    expect(Number(res.rows[0].count)).toBe(1);
  });
});
