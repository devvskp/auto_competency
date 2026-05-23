require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Configure EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'railway_competency_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// IST date formatter — available in every EJS template as formatIST(date)
const IST_OPTS_DATE = { timeZone: 'Asia/Kolkata', day: '2-digit', month: '2-digit', year: 'numeric' };
const IST_OPTS_DATETIME = { timeZone: 'Asia/Kolkata', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };

function formatIST(date, includeTime = false) {
  if (!date) return '';
  const d = (date instanceof Date) ? date : new Date(date);
  if (isNaN(d)) return '';
  const opts = includeTime ? IST_OPTS_DATETIME : IST_OPTS_DATE;
  // Returns DD/MM/YYYY or DD/MM/YYYY, HH:MM:SS
  return d.toLocaleString('en-IN', opts).replace(/\//g, '-');
}

// Share session user and helpers with all templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.formatIST = formatIST;
  next();
});

// Helper Middlewares
const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.user_type !== role) {
      return res.status(403).render('error', { 
        message: 'Access Denied: You do not have permissions to view this page.' 
      });
    }
    next();
  };
};

// --- AUTHENTICATION ROUTES ---

app.get('/', (req, res) => {
  if (req.session.user) {
    const role = req.session.user.user_type;
    if (role === 'admin') return res.redirect('/admin');
    if (role === 'FA') return res.redirect('/fa');
    if (role === 'AA') return res.redirect('/aa');
    if (role === 'CE') return res.redirect('/ce');
  }
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.render('login', { error: 'Invalid username or password.' });
    }
    
    const user = result.rows[0];
    if (user.password !== password) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    // Save session
    req.session.user = {
      id: user.id,
      name: user.name,
      designation: user.designation,
      user_type: user.user_type,
      username: user.username
    };

    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: `An error occurred during login: ${err.message}. Please try again.` });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});


// --- ADMIN ROUTES (User Management) ---

app.get('/admin', requireLogin, requireRole('admin'), async (req, res) => {
  try {
    const usersResult = await pool.query('SELECT * FROM users ORDER BY user_type, name');
    res.render('admin', { users: usersResult.rows, error: null, success: null });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).send('Database error.');
  }
});

app.post('/admin/users/create', requireLogin, requireRole('admin'), async (req, res) => {
  const { name, designation, user_type, username, password } = req.body;
  try {
    await pool.query(
      'INSERT INTO users (name, designation, user_type, username, password) VALUES ($1, $2, $3, $4, $5)',
      [name, designation, user_type, username, password]
    );
    res.redirect('/admin?success=User created successfully!');
  } catch (err) {
    console.error('Error creating user:', err);
    res.redirect('/admin?error=Error creating user. Username might already exist.');
  }
});

app.post('/admin/users/update', requireLogin, requireRole('admin'), async (req, res) => {
  const { id, name, designation, user_type, username, password } = req.body;
  try {
    await pool.query(
      'UPDATE users SET name = $1, designation = $2, user_type = $3, username = $4, password = $5 WHERE id = $6',
      [name, designation, user_type, username, password, id]
    );
    res.redirect('/admin?success=User updated successfully!');
  } catch (err) {
    console.error('Error updating user:', err);
    res.redirect('/admin?error=Error updating user.');
  }
});

app.post('/admin/users/delete', requireLogin, requireRole('admin'), async (req, res) => {
  const { id } = req.body;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.redirect('/admin?success=User deleted successfully!');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.redirect('/admin?error=Error deleting user.');
  }
});


// --- FA (TRAINER / FORWARDING AUTHORITY) ROUTES ---

app.get('/fa', requireLogin, requireRole('FA'), async (req, res) => {
  try {
    // Get all certificates forwarded by this user
    const certsResult = await pool.query(
      'SELECT * FROM certificates WHERE forwarded_by = $1 ORDER BY created_at DESC',
      [req.session.user.username]
    );

    const success = req.query.success || null;
    const error = req.query.error || null;

    res.render('fa', { 
      certificates: certsResult.rows, 
      ceUsers: [], // Kept as empty array to support any legacy references
      success, 
      error 
    });
  } catch (err) {
    console.error('FA Dashboard error:', err);
    res.status(500).send('Database error.');
  }
});

app.post('/fa/certificates/create', requireLogin, requireRole('FA'), async (req, res) => {
  const { employee_id, employee_name, designation, certified_date } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Check if user already exists
    const userCheck = await client.query('SELECT * FROM users WHERE username = $1', [employee_id]);
    
    if (userCheck.rows.length === 0) {
      // Automatically register the CE user (username and password set to employee_id)
      await client.query(
        `INSERT INTO users (name, designation, user_type, username, password)
         VALUES ($1, $2, 'CE', $3, $3)`,
        [employee_name, designation, employee_id]
      );
      console.log(`Automatically registered user CE: ${employee_id}`);
    }

    // 2. Calculate Validity Date (6 months minus 1 day)
    const certDateObj = new Date(certified_date);
    const validDateObj = new Date(certDateObj);
    validDateObj.setMonth(validDateObj.getMonth() + 6);
    validDateObj.setDate(validDateObj.getDate() - 1);
    const formattedValidDate = validDateObj.toISOString().split('T')[0];

    // 3. Insert pending certificate request
    await client.query(
      `INSERT INTO certificates (employee_id, employee_name, designation, certified_date, valid_upto, status, forwarded_by)
       VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)`,
      [employee_id, employee_name, designation, certified_date, formattedValidDate, req.session.user.username]
    );

    await client.query('COMMIT');
    res.redirect('/fa?success=Certificate request forwarded successfully to Approving Authority (AA).');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error forwarding certificate:', err);
    res.redirect('/fa?error=Error forwarding certificate request.');
  } finally {
    client.release();
  }
});


// --- AA (APPROVING AUTHORITY) ROUTES ---

app.get('/aa', requireLogin, requireRole('AA'), async (req, res) => {
  try {
    // Get all pending certificates
    const pendingCertsResult = await pool.query(
      `SELECT c.*, f.name as forwarded_by_name 
       FROM certificates c 
       LEFT JOIN users f ON c.forwarded_by = f.username 
       WHERE c.status = 'PENDING' 
       ORDER BY c.created_at ASC`
    );

    // Get all certificates approved/rejected by this AA
    const historyResult = await pool.query(
      `SELECT c.*, f.name as forwarded_by_name 
       FROM certificates c 
       LEFT JOIN users f ON c.forwarded_by = f.username 
       WHERE c.status != 'PENDING' AND c.approved_by = $1
       ORDER BY c.approved_at DESC`,
      [req.session.user.username]
    );

    const success = req.query.success || null;
    const error = req.query.error || null;

    res.render('aa', {
      pendingCertificates: pendingCertsResult.rows,
      historyCertificates: historyResult.rows,
      success,
      error
    });
  } catch (err) {
    console.error('AA dashboard error:', err);
    res.status(500).send('Database error.');
  }
});

app.post('/aa/certificates/approve/:id', requireLogin, requireRole('AA'), async (req, res) => {
  const certId = req.params.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Fetch certificate to verify it is pending
    const checkResult = await client.query(
      'SELECT * FROM certificates WHERE id = $1 FOR UPDATE',
      [certId]
    );

    if (checkResult.rows.length === 0 || checkResult.rows[0].status !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.redirect('/aa?error=Certificate request not found or is already processed.');
    }

    // 2. Determine the next serial number for year 2026 (or extract year from certified date)
    // The format is: WTS/AC/118/2026/XXXX
    // We search the certificates table for the highest serial number in 2026
    const certifiedDate = new Date(checkResult.rows[0].certified_date);
    const certYear = certifiedDate.getFullYear();
    const certMonth = String(certifiedDate.getMonth() + 1).padStart(2, '0');

    const serialResult = await client.query(
      `SELECT COALESCE(MAX(serial_number), 0) as max_sn 
       FROM certificates 
       WHERE cert_number LIKE $1`,
      [`WTS/AC/118/${certYear}/${certMonth}/%`]
    );

    const nextSerial = serialResult.rows[0].max_sn + 1;
    const paddedSerial = String(nextSerial).padStart(2, '0');
    const certNumber = `WTS/AC/118/${certYear}/${certMonth}/${paddedSerial}`;

    // 3. Update the certificate row
    await client.query(
      `UPDATE certificates 
       SET cert_number = $1, serial_number = $2, status = 'APPROVED', approved_by = $3, approved_at = (NOW() AT TIME ZONE 'Asia/Kolkata')
       WHERE id = $4`,
      [certNumber, nextSerial, req.session.user.username, certId]
    );

    await client.query('COMMIT');
    res.redirect(`/aa?success=Certificate approved successfully! Certificate No: ${certNumber}`);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error approving certificate:', err);
    res.redirect('/aa?error=Error occurred during approval transaction.');
  } finally {
    client.release();
  }
});

app.post('/aa/certificates/approve-batch', requireLogin, requireRole('AA'), async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ success: false, error: 'No certificates selected for approval.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const approvedCertNumbers = [];

    for (const certId of ids) {
      // 1. Fetch certificate to verify it is pending
      const checkResult = await client.query(
        'SELECT * FROM certificates WHERE id = $1 AND status = \'PENDING\' FOR UPDATE',
        [certId]
      );

      if (checkResult.rows.length === 0) {
        continue;
      }

      const cert = checkResult.rows[0];
      const certifiedDate = new Date(cert.certified_date);
      const certYear = certifiedDate.getFullYear();
      const certMonth = String(certifiedDate.getMonth() + 1).padStart(2, '0');

      // Get next serial number
      const serialResult = await client.query(
        `SELECT COALESCE(MAX(serial_number), 0) as max_sn 
         FROM certificates 
         WHERE cert_number LIKE $1`,
        [`WTS/AC/118/${certYear}/${certMonth}/%`]
      );

      const nextSerial = serialResult.rows[0].max_sn + 1;
      const paddedSerial = String(nextSerial).padStart(2, '0');
      const certNumber = `WTS/AC/118/${certYear}/${certMonth}/${paddedSerial}`;

      // Update the certificate row
      await client.query(
        `UPDATE certificates 
         SET cert_number = $1, serial_number = $2, status = 'APPROVED', approved_by = $3, approved_at = (NOW() AT TIME ZONE 'Asia/Kolkata')
         WHERE id = $4`,
        [certNumber, nextSerial, req.session.user.username, certId]
      );

      approvedCertNumbers.push(certNumber);
    }

    await client.query('COMMIT');
    res.json({ 
      success: true, 
      count: approvedCertNumbers.length, 
      message: `Successfully approved/granted ${approvedCertNumbers.length} certificate(s).` 
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error approving batch:', err);
    res.status(500).json({ success: false, error: 'Error occurred during batch approval transaction.' });
  } finally {
    client.release();
  }
});


app.post('/aa/certificates/reject/:id', requireLogin, requireRole('AA'), async (req, res) => {
  const certId = req.params.id;
  try {
    const result = await pool.query(
      `UPDATE certificates 
       SET status = 'REJECTED', approved_by = $1, approved_at = (NOW() AT TIME ZONE 'Asia/Kolkata')
       WHERE id = $2 AND status = 'PENDING'`,
      [req.session.user.username, certId]
    );

    if (result.rowCount === 0) {
      return res.redirect('/aa?error=Certificate not found or already processed.');
    }

    res.redirect('/aa?success=Certificate request rejected.');
  } catch (err) {
    console.error('Error rejecting certificate:', err);
    res.redirect('/aa?error=Error occurred while rejecting request.');
  }
});


// --- CE (CERTIFIED EMPLOYEE) ROUTES ---

app.get('/ce', requireLogin, requireRole('CE'), async (req, res) => {
  try {
    // Get all approved certificates for this user
    const result = await pool.query(
      `SELECT c.*, f.name as forwarded_by_name, a.name as approved_by_name, a.designation as approved_by_designation
       FROM certificates c
       LEFT JOIN users f ON c.forwarded_by = f.username
       LEFT JOIN users a ON c.approved_by = a.username
       WHERE c.employee_id = $1 AND c.status = 'APPROVED'
       ORDER BY c.certified_date DESC`,
      [req.session.user.username]
    );

    res.render('ce', { certificates: result.rows });
  } catch (err) {
    console.error('CE Dashboard error:', err);
    res.status(500).send('Database error.');
  }
});


// --- GENERAL CERTIFICATE VIEW ROUTE ---

app.get('/certificate/view/:id', requireLogin, async (req, res) => {
  const certId = req.params.id;
  try {
    // Fetch certificate and include details of employee, FA, and AA
    const result = await pool.query(
      `SELECT c.*, 
              u.name as employee_real_name, u.designation as employee_designation,
              f.name as fa_name, f.designation as fa_designation,
              a.name as aa_name, a.designation as aa_designation
       FROM certificates c
       LEFT JOIN users u ON c.employee_id = u.username
       LEFT JOIN users f ON c.forwarded_by = f.username
       LEFT JOIN users a ON c.approved_by = a.username
       WHERE c.id = $1`,
      [certId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('Certificate not found.');
    }

    const certificate = result.rows[0];

    // Authorization: User must be Admin, FA who forwarded, AA who approved, or the CE employee themselves.
    const currUser = req.session.user;
    if (
      currUser.user_type !== 'admin' &&
      currUser.username !== certificate.employee_id &&
      currUser.username !== certificate.forwarded_by &&
      currUser.username !== certificate.approved_by
    ) {
      return res.status(403).send('Unauthorized: You are not permitted to view this certificate.');
    }

    if (certificate.status !== 'APPROVED') {
      return res.status(400).send('Certificate is not approved yet.');
    }

    res.render('certificate', { certificate });
  } catch (err) {
    console.error('Error fetching certificate:', err);
    res.status(500).send('Database error.');
  }
});


// --- BATCH CERTIFICATE PRINTING ROUTE ---
app.get('/certificate/print-batch', requireLogin, async (req, res) => {
  let ids = req.query.ids;
  if (!ids) {
    return res.status(400).send('No certificates selected.');
  }
  if (!Array.isArray(ids)) {
    ids = [ids];
  }
  
  try {
    const result = await pool.query(
      `SELECT c.*, 
              u.name as employee_real_name, u.designation as employee_designation,
              f.name as fa_name, f.designation as fa_designation,
              a.name as aa_name, a.designation as aa_designation
       FROM certificates c
       LEFT JOIN users u ON c.employee_id = u.username
       LEFT JOIN users f ON c.forwarded_by = f.username
       LEFT JOIN users a ON c.approved_by = a.username
       WHERE c.id = ANY($1::int[]) AND c.status = 'APPROVED'`,
      [ids]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('No valid approved certificates found for printing.');
    }

    res.render('certificate_batch', { certificates: result.rows });
  } catch (err) {
    console.error('Error fetching batch certificates:', err);
    res.status(500).send('Database error.');
  }
});


// Generic error view (fallback)
app.use((req, res) => {
  res.status(404).send('Page Not Found');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
