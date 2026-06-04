require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Neon serverless connections
  }
});

async function setupDatabase() {
  const client = await pool.connect();
  try {
    console.log('Connected to Neon database. Initializing schema...');

    // Drop tables if they exist to start fresh
    await client.query('DROP TABLE IF EXISTS certificates CASCADE;');
    await client.query('DROP TABLE IF EXISTS employees CASCADE;');
    await client.query('DROP TABLE IF EXISTS users CASCADE;');

    console.log('Creating "users" table...');
    await client.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        designation VARCHAR(100) NOT NULL,
        user_type VARCHAR(20) NOT NULL CHECK (user_type IN ('admin', 'FA', 'AA')),
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL
      );
    `);

    console.log('Creating "employees" table...');
    await client.query(`
      CREATE TABLE employees (
        id SERIAL PRIMARY KEY,
        employee_id VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        designation VARCHAR(100) NOT NULL,
        password VARCHAR(100) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED')),
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        approved_at TIMESTAMP
      );
    `);

    console.log('Creating "certificates" table...');
    await client.query(`
      CREATE TABLE certificates (
        id SERIAL PRIMARY KEY,
        employee_id VARCHAR(50) NOT NULL,
        employee_name VARCHAR(100) NOT NULL,
        designation VARCHAR(100) NOT NULL,
        certified_date DATE NOT NULL,
        valid_upto DATE NOT NULL,
        cert_number VARCHAR(100) UNIQUE,
        serial_number INTEGER,
        status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
        forwarded_by VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
        approved_by VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        approved_at TIMESTAMP
      );
    `);

    console.log('Inserting seed users...');
    const insertUserQuery = `
      INSERT INTO users (name, designation, user_type, username, password)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (username) DO NOTHING;
    `;

    // 1. M V D V Prasad (Trainer / FA)
    await client.query(insertUserQuery, [
      'M V D V Prasad',
      'TMC / VSKP',
      'FA',
      'tmc',
      'fa@tmc'
    ]);

    // 2. S. Kishore (Approving Authority / AA)
    await client.query(insertUserQuery, [
      'S. Kishore',
      'Ch.TI (Traffic Safety) / VSKP',
      'AA',
      'cti',
      'aa@cti'
    ]);

    // 3. K Suresh (Admin)
    await client.query(insertUserQuery, [
      'K Suresh',
      'Sr TMR (G)/MIPM',
      'admin',
      'admin',
      'interOP@123'
    ]);

    console.log('Inserting seed employees...');
    const insertEmployeeQuery = `
      INSERT INTO employees (employee_id, name, designation, password, status, approved_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (employee_id) DO NOTHING;
    `;

    // 4. Kommara Suresh (Certified Employee / CE)
    await client.query(insertEmployeeQuery, [
      'mipm7602',
      'Kommara Suresh',
      'Sr TMR (G)/MIPM',
      'mipm7602',
      'APPROVED',
      new Date()
    ]);

    console.log('Inserting sample approved certificate...');
    // Seed approved certificate for Kommara Suresh
    // Name: Kommara Suresh, Designation: Sr TMR (G)/MIPM, Username: mipm7602
    // certified date: 21-05-2026, valid upto: 20-11-2026, cert number: VTS/AC/118/2026/0001
    await client.query(`
      INSERT INTO certificates (
        employee_id, employee_name, designation, certified_date, valid_upto, 
        cert_number, serial_number, status, forwarded_by, approved_by, approved_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
    `, [
      'mipm7602',
      'Kommara Suresh',
      'Sr TMR (G)/MIPM',
      '2026-05-21', // 21-05-2026
      '2026-11-20', // 20-11-2026
      'VTS/AC/118/2026/0001',
      1,
      'APPROVED',
      'tmc', // Forwarded by FA Prasad
      'cti', // Approved by AA Kishore
      new Date('2026-05-21')
    ]);

    console.log('Database setup and seeding completed successfully!');
  } catch (err) {
    console.error('Error during database setup:', err);
  } finally {
    client.release();
    await pool.end();
  }
}

setupDatabase();
