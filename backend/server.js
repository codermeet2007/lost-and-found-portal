const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Simple CORS (sab origin allow)
app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ UPLOADS FOLDER CREATE IF NOT EXISTS
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Uploads folder created successfully');
}
app.use('/uploads', express.static(uploadsDir));

// Database connection - PASSWORD CHANGE KARNA
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Meet1234@',
  database: 'lost_and_found'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.log('Database connection failed. Please check your MySQL installation and password.');
    console.log('Error: ', err.message);
    return;
  }
  console.log('Connected to MySQL database');
  initializeDatabase();
});

const initializeDatabase = () => {
  const createClaimsTable = `
    CREATE TABLE IF NOT EXISTS claims (
      id INT AUTO_INCREMENT PRIMARY KEY,
      report_id INT NOT NULL,
      claimer_id INT NOT NULL,
      message TEXT NOT NULL,
      status ENUM('pending','approved','rejected') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;

  const createNotificationsTable = `
    CREATE TABLE IF NOT EXISTS notifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      link VARCHAR(255),
      is_read TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  db.query(createClaimsTable, (err) => {
    if (err) {
      console.error('Failed to ensure claims table exists:', err.message);
    }
  });

  db.query(createNotificationsTable, (err) => {
    if (err) {
      console.error('Failed to ensure notifications table exists:', err.message);
    }
  });

  db.query('SHOW COLUMNS FROM reports LIKE "status"', (err, results) => {
    if (!err && results.length === 0) {
      const addStatusColumn = `
        ALTER TABLE reports 
        ADD COLUMN status ENUM('open','pending_claim','matched','closed') DEFAULT 'open' AFTER reward
      `;
      db.query(addStatusColumn, (alterErr) => {
        if (alterErr) {
          console.error('Failed to add status column to reports table:', alterErr.message);
        }
      });
    }
  });
};

const notifyUser = (userId, title, body, link = null) => {
  if (!userId) return;
  db.query(
    'INSERT INTO notifications (user_id, title, body, link) VALUES (?, ?, ?, ?)',
    [userId, title, body, link],
    (err) => {
      if (err) {
        console.error('Notification insert error:', err.message);
      }
    }
  );
};

const updateReportStatus = (reportId, status) => {
  if (!reportId || !status) return;
  db.query('UPDATE reports SET status = ? WHERE id = ?', [status, reportId], (err) => {
    if (err) {
      console.error('Failed to update report status:', err.message);
    }
  });
};

const findPotentialMatches = (report, callback) => {
  if (!report || !report.category || !report.location || !report.date) {
    return callback([]);
  }

  const query = `
    SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email
    FROM reports r
    JOIN lostandfound u ON r.user_id = u.id
    WHERE r.id != ?
      AND r.user_id != ?
      AND r.type != ?
      AND r.category = ?
      AND (r.location LIKE ? OR ? LIKE CONCAT('%', r.location, '%'))
      AND r.date IS NOT NULL
      AND ABS(TIMESTAMPDIFF(DAY, r.date, ?)) <= 30
    ORDER BY ABS(TIMESTAMPDIFF(DAY, r.date, ?)) ASC
    LIMIT 5
  `;

  const params = [
    report.id || 0,
    report.userId,
    report.type,
    report.category,
    `%${report.location}%`,
    report.location,
    report.date,
    report.date
  ];

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Match query error:', err.message);
      return callback([]);
    }
    callback(results || []);
  });
};

// Configure file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Signup endpoint - PHONE NUMBER ADD KIYA
app.post('/api/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  
  try {
    // Check if user already exists
    db.query('SELECT * FROM lostandfound WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.log('Database Error in signup:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ error: 'User already exists with this email' });
      }
      
      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      // Insert user into database with PHONE NUMBER
      db.query(
        'INSERT INTO lostandfound (name, email, phone, password) VALUES (?, ?, ?, ?)',
        [name, email, phone, hashedPassword],
        (err, results) => {
          if (err) {
            console.log('Database Insert Error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          res.status(201).json({ 
            message: 'User created successfully',
            userId: results.insertId 
          });
        }
      );
    });
  } catch (error) {
    console.log('Signup Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Find user by email
  db.query('SELECT * FROM lostandfound WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.log('Database Error in login:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = results[0];
    
    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Don't send password back to client
    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      profilePicture: user.profile_picture
    };
    
    res.json({ 
      message: 'Login successful', 
      user: userResponse 
    });
  });
});

// Upload profile picture
app.post('/api/upload-profile', upload.single('profilePicture'), (req, res) => {
  const userId = req.body.userId;
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const profilePicturePath = `uploads/${req.file.filename}`;
  
  console.log('File uploaded successfully:', req.file);
  
  // Update user profile picture in database
  db.query(
    'UPDATE lostandfound SET profile_picture = ? WHERE id = ?',
    [profilePicturePath, userId],
    (err, results) => {
      if (err) {
        console.log('Database Update Error:', err);
        return res.status(500).json({ error: 'Failed to update profile picture' });
      }
      
      res.json({ 
        message: 'Profile picture updated successfully',
        profilePicture: profilePicturePath 
      });
    }
  );
});

// Get user data
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  
  db.query('SELECT id, name, email, phone, profile_picture FROM lostandfound WHERE id = ?', [userId], (err, results) => {
    if (err) {
      console.log('Database Error in get user:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user: results[0] });
  });
});

// ✅ NEW: Save report to DATABASE (NOT JSON FILE)
app.post('/api/save-report', upload.single('itemPhoto'), async (req, res) => {
  const reportData = req.body;
  const user = JSON.parse(reportData.userData);
  
  try {
    let photoPath = null;
    
    // If photo uploaded, save it
    if (req.file) {
      photoPath = `uploads/${req.file.filename}`;
    }
    
    // Insert report into MySQL database
    db.query(
      `INSERT INTO reports 
      (type, item_name, category, description, location, date, contact, reward, photo_path, user_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        reportData.type,
        reportData.itemName,
        reportData.category,
        reportData.description,
        reportData.location,
        reportData.date,
        reportData.contact,
        reportData.reward || null,
        photoPath,
        user.id
      ],
      (err, results) => {
        if (err) {
          console.log('Database Insert Error:', err);
          return res.status(500).json({ error: 'Failed to save report to database' });
        }
        
        const newReport = {
          id: results.insertId,
          type: reportData.type,
          category: reportData.category,
          location: reportData.location,
          date: reportData.date,
          userId: user.id
        };

        findPotentialMatches(newReport, (matches) => {
          const formattedMatches = matches.map(match => ({
            id: match.id,
            itemName: match.item_name,
            type: match.type,
            category: match.category,
            location: match.location,
            date: match.date,
            contact: match.contact,
            reward: match.reward,
            photo: match.photo_path ? `http://localhost:3000/${match.photo_path}` : null,
            userId: match.user_id,
            userName: match.user_name,
            userPhone: match.user_phone,
            userEmail: match.user_email
          }));

          if (formattedMatches.length > 0) {
            formattedMatches.forEach(match => {
              notifyUser(
                user.id,
                'Potential match found',
                `We found a ${match.type} report that looks similar to "${match.itemName}".`,
                null
              );

              notifyUser(
                match.userId,
                'Potential match found',
                `Your report "${match.itemName}" might match a new ${reportData.type} report.`,
                null
              );
            });
          }

          res.json({ 
            message: 'Report saved successfully to database',
            reportId: results.insertId,
            matches: formattedMatches
          });
        });
      }
    );
  } catch (error) {
    console.error('Error saving report:', error);
    res.status(500).json({ error: 'Failed to save report' });
  }
});

// ✅ NEW: Get all reports from DATABASE
app.get('/api/reports', (req, res) => {
  const { type, category, q, location, fromDate, toDate, userId } = req.query;
  const conditions = [];
  const params = [];

  if (type) {
    conditions.push('r.type = ?');
    params.push(type);
  }

  if (category) {
    conditions.push('r.category = ?');
    params.push(category);
  }

  if (location) {
    conditions.push('r.location LIKE ?');
    params.push(`%${location}%`);
  }

  if (userId) {
    conditions.push('r.user_id = ?');
    params.push(userId);
  }

  if (fromDate) {
    conditions.push('DATE(r.date) >= DATE(?)');
    params.push(fromDate);
  }

  if (toDate) {
    conditions.push('DATE(r.date) <= DATE(?)');
    params.push(toDate);
  }

  if (q) {
    conditions.push('(r.item_name LIKE ? OR r.description LIKE ? OR r.location LIKE ?)');
    const searchTerm = `%${q}%`;
    params.push(searchTerm, searchTerm, searchTerm);
  }

  let query = `
    SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email 
    FROM reports r 
    JOIN lostandfound u ON r.user_id = u.id
  `;

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }

  query += ' ORDER BY r.created_at DESC LIMIT 100';

  db.query(query, params, (err, results) => {
    if (err) {
      console.log('Database Error in get reports:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    const formattedReports = results.map(report => ({
      type: report.type,
      itemName: report.item_name,
      category: report.category,
      description: report.description,
      location: report.location,
      date: report.date,
      contact: report.contact,
      reward: report.reward,
      photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
      userId: report.user_id,
      id: report.id.toString(),
      createdAt: report.created_at,
      userName: report.user_name,
      userPhone: report.user_phone,
      userEmail: report.user_email,
      status: report.status || 'open'
    }));
    
    res.json({ reports: formattedReports });
  });
});

// ✅ NEW: Get user's own reports
app.get('/api/user-reports/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.query(
    `SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC`,
    [userId],
    (err, results) => {
      if (err) {
        console.log('Database Error in get user reports:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      const formattedReports = results.map(report => ({
        type: report.type,
        itemName: report.item_name,
        category: report.category,
        description: report.description,
        location: report.location,
        date: report.date,
        contact: report.contact,
        reward: report.reward,
        photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        status: report.status || 'open'
      }));
      
      res.json({ reports: formattedReports });
    }
  );
});

// ✅ NEW: Delete report from DATABASE
app.delete('/api/reports/:reportId', (req, res) => {
  const reportId = req.params.reportId;
  
  db.query('DELETE FROM reports WHERE id = ?', [reportId], (err, results) => {
    if (err) {
      console.log('Database Error in delete report:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ message: 'Report deleted successfully' });
  });
});

// ✅ CLAIM: Submit claim for a report
app.post('/api/reports/:reportId/claims', (req, res) => {
  const reportId = req.params.reportId;
  const { claimerId, message } = req.body;

  if (!claimerId || !message) {
    return res.status(400).json({ error: 'Claimer ID and message are required' });
  }

  db.query('SELECT * FROM reports WHERE id = ?', [reportId], (err, reportResults) => {
    if (err) {
      console.error('Claim lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (reportResults.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const report = reportResults[0];

    if (report.user_id === Number(claimerId)) {
      return res.status(400).json({ error: 'You cannot claim your own report' });
    }

    db.query(
      'INSERT INTO claims (report_id, claimer_id, message) VALUES (?, ?, ?)',
      [reportId, claimerId, message],
      (insertErr, result) => {
        if (insertErr) {
          console.error('Claim insert error:', insertErr);
          return res.status(500).json({ error: 'Failed to submit claim' });
        }

        updateReportStatus(reportId, 'pending_claim');
        notifyUser(
          report.user_id,
          'New claim received',
          `Someone submitted a claim for "${report.item_name}". Please review it.`,
          null
        );
        notifyUser(
          claimerId,
          'Claim submitted',
          `Your claim for "${report.item_name}" has been sent to the owner.`,
          null
        );

        res.json({
          message: 'Claim submitted successfully',
          claimId: result.insertId
        });
      }
    );
  });
});

// ✅ CLAIM: Get claims for a report (for owner/admin)
app.get('/api/reports/:reportId/claims', (req, res) => {
  const reportId = req.params.reportId;

  const query = `
    SELECT c.*, u.name as claimer_name, u.email as claimer_email, u.phone as claimer_phone
    FROM claims c
    JOIN lostandfound u ON c.claimer_id = u.id
    WHERE c.report_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [reportId], (err, results) => {
    if (err) {
      console.error('Get report claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Get claims submitted by a user
app.get('/api/user/claims/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT c.*, r.item_name, r.type as report_type, r.status as report_status
    FROM claims c
    JOIN reports r ON c.report_id = r.id
    WHERE c.claimer_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Get user claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Get incoming claims for user's reports
app.get('/api/user/incoming-claims/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT c.*, r.item_name, r.type as report_type, u.name as claimer_name, u.email as claimer_email, u.phone as claimer_phone
    FROM claims c
    JOIN reports r ON c.report_id = r.id
    JOIN lostandfound u ON c.claimer_id = u.id
    WHERE r.user_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Get incoming claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Update claim status
app.patch('/api/claims/:claimId/status', (req, res) => {
  const claimId = req.params.claimId;
  const { status } = req.body;
  const allowedStatuses = ['pending', 'approved', 'rejected'];

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const lookupQuery = `
    SELECT c.*, r.item_name, r.user_id as owner_id 
    FROM claims c 
    JOIN reports r ON c.report_id = r.id 
    WHERE c.id = ?
  `;

  db.query(lookupQuery, [claimId], (err, results) => {
    if (err) {
      console.error('Claim status lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Claim not found' });
    }

    const claim = results[0];

    db.query('UPDATE claims SET status = ? WHERE id = ?', [status, claimId], (updateErr) => {
      if (updateErr) {
        console.error('Claim status update error:', updateErr);
        return res.status(500).json({ error: 'Failed to update claim status' });
      }

      if (status === 'approved') {
        updateReportStatus(claim.report_id, 'closed');
        notifyUser(
          claim.claimer_id,
          'Claim approved',
          `Your claim for "${claim.item_name}" was approved.`,
          null
        );
      } else if (status === 'rejected') {
        updateReportStatus(claim.report_id, 'open');
        notifyUser(
          claim.claimer_id,
          'Claim rejected',
          `Your claim for "${claim.item_name}" was rejected.`,
          null
        );
      } else {
        updateReportStatus(claim.report_id, 'pending_claim');
      }

      res.json({ message: 'Claim status updated successfully' });
    });
  });
});

// ✅ MATCHES: Fetch potential matches for current user
app.get('/api/matches/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      r.id as report_id,
      r.item_name as report_item_name,
      r.type as report_type,
      r.category as report_category,
      r.location as report_location,
      r.date as report_date,
      m.id as match_id,
      m.item_name as match_item_name,
      m.type as match_type,
      m.location as match_location,
      m.date as match_date,
      m.photo_path as match_photo_path,
      m.user_id as match_user_id,
      u.name as match_user_name,
      u.phone as match_user_phone,
      u.email as match_user_email
    FROM reports r
    JOIN reports m ON m.type != r.type
      AND m.category = r.category
      AND m.user_id != r.user_id
      AND (m.location LIKE CONCAT('%', r.location, '%') OR r.location LIKE CONCAT('%', m.location, '%'))
      AND ABS(TIMESTAMPDIFF(DAY, m.date, r.date)) <= 30
    JOIN lostandfound u ON m.user_id = u.id
    WHERE r.user_id = ?
    ORDER BY ABS(TIMESTAMPDIFF(DAY, m.date, r.date)) ASC
    LIMIT 20
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Matches lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    const matches = results.map(row => ({
      baseReport: {
        id: row.report_id,
        itemName: row.report_item_name,
        type: row.report_type,
        category: row.report_category,
        location: row.report_location,
        date: row.report_date
      },
      match: {
        id: row.match_id,
        itemName: row.match_item_name,
        type: row.match_type,
        location: row.match_location,
        date: row.match_date,
        photo: row.match_photo_path ? `http://localhost:3000/${row.match_photo_path}` : null,
        userId: row.match_user_id,
        userName: row.match_user_name,
        userPhone: row.match_user_phone,
        userEmail: row.match_user_email
      }
    }));

    res.json({ matches });
  });
});

// ✅ NOTIFICATIONS: List notifications for user
app.get('/api/notifications/:userId', (req, res) => {
  const userId = req.params.userId;

  db.query(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
    [userId],
    (err, results) => {
      if (err) {
        console.error('Notifications fetch error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ notifications: results });
    }
  );
});

// ✅ NOTIFICATIONS: Mark notification as read
app.patch('/api/notifications/:notificationId/read', (req, res) => {
  const notificationId = req.params.notificationId;

  db.query(
    'UPDATE notifications SET is_read = 1 WHERE id = ?',
    [notificationId],
    (err) => {
      if (err) {
        console.error('Notification update error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ message: 'Notification marked as read' });
    }
  );
});

// ✅ ADMIN: Admin Login - WORKING FIX
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('Admin login attempt:', username, password);
  
  // Simple admin authentication - HARDCODED
  if (username === 'admin' && password === 'admin123') {
    console.log('Admin login SUCCESS');
    res.json({ 
      message: 'Admin login successful',
      admin: { username: 'admin', role: 'admin' }
    });
  } else {
    console.log('Admin login FAILED');
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ✅ ADMIN: Get all reports (sab users ke)
app.get('/api/admin/reports', (req, res) => {
  db.query(
    `SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email 
     FROM reports r 
     JOIN lostandfound u ON r.user_id = u.id 
     ORDER BY r.created_at DESC`,
    (err, results) => {
      if (err) {
        console.log('Admin Database Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      const formattedReports = results.map(report => ({
        type: report.type,
        itemName: report.item_name,
        category: report.category,
        description: report.description,
        location: report.location,
        date: report.date,
        contact: report.contact,
        reward: report.reward,
        photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        userName: report.user_name,
        userPhone: report.user_phone,
      userEmail: report.user_email,
      status: report.status || 'open'
      }));
      
      res.json({ reports: formattedReports });
    }
  );
});

// ✅ ADMIN: Delete any report (kisi ka bhi)
app.delete('/api/admin/reports/:reportId', (req, res) => {
  const reportId = req.params.reportId;
  
  db.query('DELETE FROM reports WHERE id = ?', [reportId], (err, results) => {
    if (err) {
      console.log('Admin Delete Error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ message: 'Report deleted successfully by admin' });
  });
});

// ✅ ADMIN: Get all users
app.get('/api/admin/users', (req, res) => {
  db.query(
    'SELECT id, name, email, phone, profile_picture, created_at FROM lostandfound ORDER BY created_at DESC',
    (err, results) => {
      if (err) {
        console.log('Admin Users Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ users: results });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

