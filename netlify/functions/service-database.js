import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import multer from 'multer';
import csv from 'csv-parser';
import fs from 'fs';
import nodemailer from 'nodemailer';

const app = express();
app.use(cors());
app.use(express.json());

// Configure CORS with multiple origins
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://localhost:3000',
  'http://localhost:5173',
  'https://time-keeper-track-teacher.netlify.app',
  'https://time-keeper-track-student.netlify.app',
  'https://project-to-ipt01.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
}));

app.use(express.json());

const upload = multer({ dest: 'uploads/' });

// Centralized configuration using environment variables
const config = {
    db: {
      host: process.env.DB_HOST || 'srv1319.hstgr.io',
      user: process.env.DB_USER || 'u428388148_ecr_username',
      password: process.env.DB_PASSWORD || '3hD7n;?7qTB@',
      database: process.env.DB_NAME || 'u428388148_ecr_database',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      keepAliveInitialDelay: 10000,
      enableKeepAlive: true
    },
    email: {
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT || '587'),
      user: process.env.EMAIL_USER || 'projectipt00@gmail.com',
      password: process.env.EMAIL_PASSWORD || 'vxbx lnmy dxiy znlp',
      secure: process.env.EMAIL_SECURE === 'true' || false
    }
  };
  
  // Create connection pool using config
  const pool = mysql.createPool(config.db);
  const promisePool = pool.promise();
  
  // Email configuration using config
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
app.post('/api/auth', async (req, res) => {
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
app.all('/api/grades', upload.single('file'), async (req, res) => {
  try {
    // GET: Fetch grades
    if (req.method === 'GET') {
      const { teacherId, studentId } = req.query;
      const query = teacherId ? 
        'SELECT * FROM grades WHERE faculty_id = ?' :
        'SELECT * FROM grades WHERE student_num = ?';
      
      const [grades] = await promisePool.query(query, [teacherId || studentId]);
      return res.json({ success: true, grades });
    }
    
    // POST: Upload grades
    if (req.method === 'POST') {
      if (!req.file) return res.status(400).json({ success: false, message: 'No file' });

      const results = [];
      await new Promise((resolve, reject) => {
        fs.createReadStream(req.file.path)
          .pipe(csv())
          .on('data', (row) => {
            const prelim = parseFloat(row.PRELIM_GRADE) || 0;
            const midterm = parseFloat(row.MIDTERM_GRADE) || 0;
            const final = parseFloat(row.FINAL_GRADE) || 0;
            const gwa = (prelim + midterm + final) / 3;
            
            results.push({
              ...row,
              GWA: gwa.toFixed(2),
              REMARK: midterm && final ? (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC'
            });
          })
          .on('end', resolve)
          .on('error', reject);
      });

      for (const row of results) {
        await promisePool.query(
          'INSERT INTO grades SET ? ON DUPLICATE KEY UPDATE ?',
          [row, row]
        );
      }

      fs.unlinkSync(req.file.path);
      return res.json({ success: true, count: results.length });
    }

    return res.status(405).json({ success: false, message: 'Method not allowed' });
  } catch (error) {
    console.error('Grades error:', error);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ENDPOINT 3: Communication
app.post('/api/communicate', async (req, res) => {
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

app.listen(5000, () => {
  console.log('Server running on port 5000');
});