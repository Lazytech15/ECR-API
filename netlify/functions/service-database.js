import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import csv from 'csv-parser';
import nodemailer from 'nodemailer';
import serverless from 'serverless-http';
import multer from 'multer';
import { Buffer } from 'buffer';

const app = express();
const router = express.Router();

// Configure CORS
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5173',
  'http://localhost:5500',
  'http://localhost:5173',
  'http://localhost:3000',
  'https://ecr-api-connection-database.netlify.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json());

// Configure multer to use memory storage instead of disk storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Database configuration
const config = {
  db: {
    host: process.env.DB_HOST || 'srv1319.hstgr.io',
    user: process.env.DB_USER || 'u428388148_ecr_username',
    password: process.env.DB_PASSWORD || '3hD7n;?7qTB@',
    database: process.env.DB_NAME || 'u428388148_ecr_database',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  },
  email: {
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT || '587'),
    user: process.env.EMAIL_USER || 'projectipt00@gmail.com',
    password: process.env.EMAIL_PASSWORD || 'vxbx lnmy dxiy znlp',
    secure: process.env.EMAIL_SECURE === 'true' || false
  }
};

const pool = mysql.createPool(config.db);
const promisePool = pool.promise();

const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: config.email.port,
  secure: config.email.secure,
  auth: {
    user: config.email.user,
    pass: config.email.password
  },
  tls: { rejectUnauthorized: false }
});

// ENDPOINT 1: Authentication and User Management
router.post('/auth', async (req, res) => {
  try {
    const { action, ...data } = req.body;

    switch (action) {
      case 'login':
        const { email, password } = data;
        const sanitizedInput = email.trim().toLowerCase();

        // Check students
        const [students] = await promisePool.query(
          'SELECT * FROM students WHERE LOWER(username) = ? OR LOWER(email) = ?',
          [sanitizedInput, sanitizedInput]
        );

        if (students.length > 0) {
          const student = students[0];
          const match = await bcrypt.compare(password, student.password);
          if (match) {
            return res.json({
              success: true,
              user: {
                id: student.id,
                email: student.email,
                student_id: student.student_id,
                name: student.full_name,
                role: 'student'
              }
            });
          }
        }

        // Check teachers
        const [teachers] = await promisePool.query(
          'SELECT * FROM users WHERE LOWER(TRIM(email)) = ?',
          [sanitizedInput]
        );

        if (teachers.length > 0 && await bcrypt.compare(password, teachers[0].password)) {
          return res.json({
            success: true,
            user: {
              id: teachers[0].id,
              email: teachers[0].email,
              name: teachers[0].teacher_name,
              role: 'teacher'
            }
          });
        }

        return res.status(401).json({ success: false, message: 'Invalid credentials' });

      case 'register':
        const { studentId, firstName, middleName, lastName, course, section, trimester } = data;
        const fullName = middleName ? `${firstName} ${middleName} ${lastName}` : `${firstName} ${lastName}`;
        const username = generateUsername(firstName, lastName, studentId);
        const plainPassword = generatePassword();
        
        // Check existing
        const [existing] = await promisePool.query(
          'SELECT 1 FROM students WHERE student_id = ? OR email = ?',
          [studentId, data.email]
        );

        if (existing.length > 0) {
          return res.status(400).json({ success: false, message: 'Already registered' });
        }

        // Create new student
        const hashedPassword = await bcrypt.hash(plainPassword, 10);
        await connection.promise().query(
          'INSERT INTO students SET ?',
          {
            student_id: studentId,
            first_name: firstName,
            middle_name: middleName,
            last_name: lastName,
            full_name: fullName,
            course,
            section,
            trimester,
            email: data.email,
            username,
            password: hashedPassword
          }
        );

        // Send welcome email
        // await transporter.sendMail({
        //   from: '"ECR Online Grade" <projectipt00@gmail.com>',
        //   to: data.email,
        //   subject: 'Welcome to ECR Online Grade',
        //   html: `
        //     <h2>Welcome to ECR Online Grade</h2>
        //     <p>Your login credentials:</p>
        //     <p>Username: ${username}</p>
        //     <p>Password: ${plainPassword}</p>
        //   `
        // });

        return res.json({ success: true, credentials: { username, password: plainPassword } });

        case 'update':
          const { studentId: updateId, currentPassword, newPassword, newSection, newTrimester, newEmail, newCourse } = data;
          
            const [studentToUpdate] = await promisePool.query(
              'SELECT * FROM students WHERE student_id = ?',
              [updateId]
            );
        
            if (studentToUpdate.length === 0) {
              return res.status(404).json({ success: false, message: 'Student not found' });
            }
        
            const updates = {};
            if (newPassword) {
              if (!await bcrypt.compare(currentPassword, studentToUpdate[0].password)) {
                return res.status(401).json({ success: false, message: 'Invalid current password' });
              }
              updates.password = await bcrypt.hash(newPassword, 10);
            }
            if (newSection) updates.section = newSection;
            if (newTrimester) updates.trimester = newTrimester;
            if (newEmail) updates.email = newEmail;
            if (newCourse) updates.course = newCourse;
        
            if (Object.keys(updates).length === 0) {
              return res.json({ success: true, message: 'No changes to update' });
            }
        
            await promisePool.query(
              'UPDATE students SET ? WHERE student_id = ?',
              [updates, updateId]
            );
        
            // Broadcast update through WebSocket
            wsService.broadcast({
              type: 'database_update',
              changes: {
                students_update: [updateId]
              }
            });
        
            return res.json({ success: true, message: 'Update successful' });

      case 'get-alldata': 
        const { studentId: emailStudentId } = data;

        const [studentData] = await promisePool.query(
          'SELECT * FROM students WHERE student_id = ?',
          [emailStudentId]
        );

        if (studentData.length > 0) {
          const student = studentData[0];
          return res.json({ success: true, student });
        } else {
          return res.status(404).json({ success: false, message: 'Student not found' });
        }

      default:
        return res.status(400).json({ success: false, message: 'Invalid action' });
    }
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ENDPOINT 2: Grades Management
router.post('/grades', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const results = [];
    const fileContent = req.file.buffer.toString();
    
    // Process CSV in memory
    await new Promise((resolve, reject) => {
      const parser = csv();
      parser.on('data', (row) => {
        const prelim = parseFloat(row.PRELIM_GRADE) || 0;
        const midterm = parseFloat(row.MIDTERM_GRADE) || 0;
        const final = parseFloat(row.FINAL_GRADE) || 0;
        const gwa = (prelim + midterm + final) / 3;
        
        results.push({
          ...row,
          GWA: gwa.toFixed(2),
          REMARK: midterm && final ? (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC'
        });
      });
      
      parser.on('end', resolve);
      parser.on('error', reject);
      
      // Feed the buffer directly to the parser
      const bufferStream = require('stream').Readable.from(fileContent);
      bufferStream.pipe(parser);
    });

    // Insert results into database
    for (const row of results) {
      await promisePool.query(
        'INSERT INTO grades SET ? ON DUPLICATE KEY UPDATE ?',
        [row, row]
      );
    }

    return res.json({ success: true, count: results.length });
  } catch (error) {
    console.error('Grades error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ENDPOINT 3: Communication
router.post('/communicate', async (req, res) => {
  try {
    const { type, data } = req.body;

    switch (type) {
      case 'email':
        await transporter.sendMail({
          from: '"ECR Online Grade" <projectipt00@gmail.com>',
          to: data.to,
          subject: data.subject,
          html: data.content
        });
        return res.json({ success: true });

      case 'notification':
        // Add notification logic here if needed
        return res.json({ success: true });

      default:
        return res.status(400).json({ success: false, message: 'Invalid communication type' });
    }
  } catch (error) {
    console.error('Communication error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await pool.end();
    console.log('Pool connections closed.');
    process.exit(0);
  } catch (err) {
    console.error('Error closing pool:', err);
    process.exit(1);
  }
});

// Mount all routes under /.netlify/functions/service-database
app.use('/.netlify/functions/service-database', router);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// Export handler for Netlify Functions
export const handler = serverless(app);