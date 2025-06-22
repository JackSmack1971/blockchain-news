import { Pool } from 'pg';

export class DatabaseError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message);
    this.name = 'DatabaseError';
  }
}

const connStr = process.env.DATABASE_URL;
if (!connStr) {
  throw new DatabaseError('DATABASE_URL is required');
}

export const pool = new Pool({ connectionString: connStr, idleTimeoutMillis: 30000, max: 10 });

export async function initDb(): Promise<void> {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      wallet_address TEXT UNIQUE,
      username TEXT,
      bio TEXT,
      avatar TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
  } catch (err) {
    throw new DatabaseError('Failed to initialize database', err);
  }
}

export async function backupDatabase(path: string): Promise<void> {
  const { exec } = await import('node:child_process');
  return new Promise((resolve, reject) => {
    exec(`pg_dump ${connStr} > ${path}`, err => {
      if (err) reject(new DatabaseError('Backup failed', err));
      else resolve();
    });
  });
}

export async function restoreDatabase(path: string): Promise<void> {
  const { exec } = await import('node:child_process');
  return new Promise((resolve, reject) => {
    exec(`psql ${connStr} < ${path}`, err => {
      if (err) reject(new DatabaseError('Restore failed', err));
      else resolve();
    });
  });
}

export async function createUser(data: {id: string; email: string; passwordHash: string; username: string; walletAddress?: string;}): Promise<void> {
  try {
    await pool.query(
      'INSERT INTO users (id, email, password_hash, username, wallet_address) VALUES ($1,$2,$3,$4,$5)',
      [data.id, data.email, data.passwordHash, data.username, data.walletAddress || null]
    );
  } catch (err) {
    throw new DatabaseError('Failed to create user', err);
  }
}

export async function findUserByEmail(email: string): Promise<any | null> {
  try {
    const res = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    return res.rows[0] || null;
  } catch (err) {
    throw new DatabaseError('Failed to fetch user', err);
  }
}

export async function clearUsers(): Promise<void> {
  await pool.query('DELETE FROM users');
}

export async function findUserByWallet(address: string): Promise<any | null> {
  try {
    const res = await pool.query('SELECT * FROM users WHERE wallet_address=$1', [address]);
    return res.rows[0] || null;
  } catch (err) {
    throw new DatabaseError('Failed to fetch wallet user', err);
  }
}
