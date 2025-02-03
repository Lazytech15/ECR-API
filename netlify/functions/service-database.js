import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import csv from 'csv-parser';
import nodemailer from 'nodemailer';
import serverless from 'serverless-http';
import multer from 'multer';

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
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  },
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT),
    user: process.env.EMAIL_USER,
    password: process.env.EMAIL_PASSWORD,
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

// Helper Functions
const generateUsername = (firstName, lastName, studentId) => {
  return `${firstName.toLowerCase().substring(0, 2)}${lastName.toLowerCase().substring(0, 2)}${studentId.slice(-4)}`;
};

const generatePassword = () => {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array.from({ length: 10 }, () => charset[Math.floor(Math.random() * charset.length)]).join('');
};

// ENDPOINT 1: Authentication and User Management
router.post('/auth', async (req, res) => {
  try {
    const { action, ...data } = req.body;

    switch (action) {
      case 'login':
        await handleLogin(data, res);
        break;
      case 'register':
        await handleRegister(data, res);
        break;
      case 'update':
        await handleUpdate(data, res);
        break;
      case 'delete-student':
        await handleDeleteStudent(data, res);
        break;
      case 'delete-grade':
        await handleDeleteGrade(data, res);
        break;
      case 'get-alldata':
        await handleGetAllData(data, res);
        break;
      case 'get-teachers':
        await handleGetTeachers(data, res);
        break;
      // case 'add-teacher':
      //   await handleAddTeacher(data, res);
      //   break;
      case 'delete-teacher':
        await handleDeleteTeacher(data, res);
        break;
      default:
        res.status(400).json({ success: false, message: 'Invalid action' });
    }
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

const handleLogin = async (data, res) => {
  const { email, password } = data;
  const sanitizedInput = email.trim().toLowerCase();

  try {
    // First check if it's a teacher login
    const [teachers] = await promisePool.query(
      'SELECT * FROM teacher WHERE LOWER(username) = ? OR LOWER(personal_email) = ?',
      [sanitizedInput, sanitizedInput]
    );

    if (teachers.length > 0) {
      const teacher = teachers[0];
      const match = await bcrypt.compare(password, teacher.password);
      if (match) {
        return res.json({
          success: true,
          user: {
            id: teacher.teacher_id,
            email: teacher.personal_email,
            name: teacher.teacher_name,
            role: 'teacher'
          }
        });
      }
    }

    // Then check if it's a student login
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
            id: student.student_id,
            email: student.email,
            name: student.full_name,
            role: 'student'
          }
        });
      }
    }

    // Finally check if it's an admin login
    const [admin] = await promisePool.query(
      'SELECT * FROM admin WHERE LOWER(username) = ?',
      [sanitizedInput]
    );

    if (admin.length > 0) {
      const match = await bcrypt.compare(password, admin[0].password);
      if (match) {
        return res.json({
          success: true,
          user: {
            username: admin[0].username,
            role: 'admin'
          }
        });
      }
    }

    // If we get here, no valid user was found
    res.status(401).json({ 
      success: false, 
      message: 'Invalid credentials'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login'
    });
  }
};

// In the backend service - Modified handleRegister function
const handleRegister = async (data, res) => {
  const { studentId, firstName, lastName, course, section, academic_term, email } = data;
  const fullName = `${firstName} ${lastName}`;
  const username = generateUsername(firstName, lastName, studentId);
  const plainPassword = generatePassword();
  
  // Determine if registering a teacher or student
  const isTeacher = course === 'FACULTY';
  const tableName = isTeacher ? 'teacher' : 'students';

    // Log registration details (remove in production)
    console.log('Registration details:', {
      isTeacher,
      username,
      plainPassword,
      email: isTeacher ? 'personal_email' : 'email',
      tableName: isTeacher ? 'teacher' : 'students'
    });
  
  // Check existing
  const [existing] = await promisePool.query(
    isTeacher ?
    'SELECT 1 FROM teacher WHERE teacher_id = ? OR personal_email = ?' :
    'SELECT 1 FROM students WHERE student_id = ? OR email = ?',
    [studentId, email]
  );

  if (existing.length > 0) {
    return res.status(400).json({ success: false, message: 'Already registered' });
  }

  // Create new user
  const hashedPassword = await bcrypt.hash(plainPassword, 10);
  
  if (isTeacher) {
    await promisePool.query(
      'INSERT INTO teacher SET ?',
      {
        teacher_id: studentId,
        teacher_name: fullName,
        personal_email: email,
        username,
        password: hashedPassword
      }
    );
  } else {
    await promisePool.query(
      'INSERT INTO students SET ?',
      {
        student_id: studentId,
        first_name: firstName,
        last_name: lastName,
        full_name: fullName,
        course,
        section,
        trimester: academic_term,
        email,
        username,
        password: hashedPassword
      }
    );
  }

    // Before sending response, log the credentials
    console.log('Generated credentials:', {
      username,
      password: plainPassword
    });

  res.json({ success: true, credentials: { username, password: plainPassword } });
};

const handleUpdate = async (data, res) => {
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

  res.json({ success: true, message: 'Update successful' });
};

const handleDeleteStudent = async (data, res) => {
  const { studentId: deleteId } = data;

  // Check if student exists
  const [studentToDelete] = await promisePool.query(
    'SELECT * FROM students WHERE student_id = ?',
    [deleteId]
  );

  if (studentToDelete.length === 0) {
    return res.status(404).json({ success: false, message: 'Student not found' });
  }

  // Delete the student
  await promisePool.query(
    'DELETE FROM students WHERE student_id = ?',
    [deleteId]
  );

  res.json({
    success: true,
    message: 'Student deleted successfully',
    deletedStudent: studentToDelete[0]
  });
};

const handleDeleteGrade = async (data, res) => {
  const { ecr_name: deleteEcrName } = data;

  // Check if grade entry exists
  const [gradeToDelete] = await promisePool.query(
    'SELECT * FROM grades WHERE ecr_name = ?',
    [deleteEcrName]
  );

  if (gradeToDelete.length === 0) {
    return res.status(404).json({ success: false, message: 'Grade entry not found' });
  }

  // Delete the grade entry
  await promisePool.query(
    'DELETE FROM grades WHERE ecr_name = ?',
    [deleteEcrName]
  );

  res.json({
    success: true,
    message: 'Grade entry deleted successfully',
    deletedGrade: gradeToDelete[0]
  });
};

const handleGetAllData = async (data, res) => {
  try {
    // If studentId is provided, return specific student
    if (data.studentId) {
      const [studentData] = await promisePool.query(
        'SELECT * FROM students WHERE student_id = ?',
        [data.studentId]
      );

      if (studentData.length > 0) {
        return res.json({ success: true, student: studentData[0] });
      } else {
        return res.status(404).json({ success: false, message: 'Student not found' });
      }
    }
    
    // Otherwise return all students for admin dashboard
    const [students] = await promisePool.query(
      'SELECT student_id, full_name, course FROM students'
    );
    res.json({ success: true, students });
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const handleGetTeachers = async (data, res) => {
  try {
    const [teachers] = await promisePool.query(
      'SELECT teacher_id, teacher_name, personal_email, password, username FROM teacher'
    );
    res.json({ success: true, teachers });
  } catch (error) {
    console.error('Error fetching teachers:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// const handleAddTeacher = async (data, res) => {
//   try {
//     const { teacher_id, teacher_name, personal_email, username, password } = data;
    
//     // Check if teacher already exists
//     const [existing] = await promisePool.query(
//       'SELECT 1 FROM teacher WHERE teacher_id = ? OR personal_email = ? OR username = ?',
//       [teacher_id, personal_email, username]
//     );

//     if (existing.length > 0) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'Teacher with this ID, email, or username already exists' 
//       });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);
    
//     await promisePool.query(
//       'INSERT INTO teacher (teacher_id, teacher_name, personal_email, username, password) VALUES (?, ?, ?, ?, ?)',
//       [teacher_id, teacher_name, personal_email, username, hashedPassword]
//     );

//     res.json({ success: true, message: 'Teacher added successfully' });
//   } catch (error) {
//     console.error('Error adding teacher:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

const handleDeleteTeacher = async (data, res) => {
  try {
    const { teacherId } = data;
    
    const [result] = await promisePool.query(
      'DELETE FROM teacher WHERE teacher_id = ?',
      [teacherId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Teacher not found' });
    }

    res.json({ success: true, message: 'Teacher deleted successfully' });
  } catch (error) {
    console.error('Error deleting teacher:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ENDPOINT 2: Grades Management
router.all('/grades', upload.single('file'), async (req, res) => {
  try {
    // Get table schema information
    const [columns] = await promisePool.query(`
      SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'grades'
      ORDER BY ORDINAL_POSITION;
    `);

    // Log table structure for debugging
    console.log('Table Structure:', columns.map(col => ({
      name: col.COLUMN_NAME,
      type: col.DATA_TYPE,
      nullable: col.IS_NULLABLE,
      key: col.COLUMN_KEY
    })));

    // GET: Fetch grades
    if (req.method === 'GET') {
      await handleGetGrades(req, res, columns);
    } else if (req.method === 'POST') {
      await handlePostGrades(req, res, columns);
    } else {
      res.status(405).json({ success: false, message: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Grades error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

const handleGetGrades = async (req, res, columns) => {
  const { teacherId, studentId } = req.query;

  if (req.query.schema === 'true') {
    return res.json({
      success: true,
      columns: columns.map(col => ({
        name: col.COLUMN_NAME,
        type: col.DATA_TYPE,
        nullable: col.IS_NULLABLE,
        key: col.COLUMN_KEY
      }))
    });
  }

  const query = teacherId ?
    'SELECT * FROM grades WHERE faculty_id = ?' :
    'SELECT * FROM grades WHERE student_num = ?';

  const [grades] = await promisePool.query(query, [teacherId || studentId]);
  res.json({ success: true, grades });
};

const handlePostGrades = async (req, res, columns) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });

  const results = [];
  const columnNames = columns.map(col => col.COLUMN_NAME.toLowerCase());

  // Create a readable stream from the buffer
  const bufferStream = new require('stream').Readable();
  bufferStream.push(req.file.buffer);
  bufferStream.push(null);

  await new Promise((resolve, reject) => {
    bufferStream
      .pipe(csv())
      .on('data', (row) => {
        // Transform row keys to match database column names
        const transformedRow = {};
        Object.entries(row).forEach(([key, value]) => {
          const normalizedKey = key.toLowerCase();
          if (columnNames.includes(normalizedKey)) {
            transformedRow[normalizedKey] = value;
          }
        });

        const prelim = parseFloat(row.PRELIM_GRADE) || 0;
        const midterm = parseFloat(row.MIDTERM_GRADE) || 0;
        const final = parseFloat(row.FINAL_GRADE) || 0;
        const gwa = (prelim + midterm + final) / 3;

        transformedRow.gwa = gwa.toFixed(2);
        transformedRow.remark = midterm && final ?
          (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC';

        results.push(transformedRow);
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

  res.json({
    success: true,
    count: results.length,
    tableInfo: {
      columnCount: columns.length,
      columns: columns.map(col => col.COLUMN_NAME)
    }
  });
};

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
        res.json({ success: true });
        break;
      case 'notification':
        // Add notification logic here if needed
        res.json({ success: true });
        break;
      default:
        res.status(400).json({ success: false, message: 'Invalid communication type' });
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
