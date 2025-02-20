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
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://127.0.0.1:5500',
      'http://127.0.0.1:5173',
      'http://localhost:5500',
      'http://localhost:5173',
      'http://localhost:3000',
      'https://mailer.cyberdyne.top',
      'https://ecr-api-connection-database.netlify.app'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
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
const generateStudent = (firstName, lastName, studentId) => {
  return `${firstName.toLowerCase().substring(0, 2)}${lastName.toLowerCase().substring(0, 2)}${studentId.slice(-4)}`;
};

const generateTeacher = (fullName, teacherId) => {
  // Split the full name and take first and last parts
  const nameParts = fullName.trim().split(' ');
  const firstName = nameParts[0];
  const lastName = nameParts[nameParts.length - 1];

  // Take first 2 letters of first name and last name, combine with last 4 digits of ID
  return `${firstName.toLowerCase().substring(0, 2)}${lastName.toLowerCase().substring(0, 2)}${teacherId.slice(-4)}`;
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
      case 'register-teacher':  // New action for teacher registration
        await handleTeacherRegister(data, res);
        break;
      case 'update':
        await handleUpdate(data, res);
        break;
      case 'delete-student':
        await handleDeleteStudent(data, res);
        break;
      case 'delete-teacher':   // Add teacher deletion
        await handleDeleteTeacher(data, res);
        break;
      case 'delete-grade':
        await handleDeleteGrade(data, res);
        break;
      case 'get-alldata':
        await handleGetAllData(data, res);
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
  const { loginInput, loginType, password } = data;
  const sanitizedInput = loginInput.trim().toLowerCase();

  console.log('Login attempt:', { loginType, sanitizedInput });

  try {
    // 1. Check Students
    let query = 'SELECT * FROM students WHERE ';
    if (loginType === 'email') {
      query += 'LOWER(email) = ?';
    } else {
      query += 'LOWER(username) = ?';
    }

    const [students] = await promisePool.query(query, [sanitizedInput]);
    console.log('Student check:', { found: students.length > 0 });

    if (students.length > 0) {
      const student = students[0];
      const passwordMatch = await bcrypt.compare(password, student.password);

      console.log('Student password check:', { matches: passwordMatch });

      if (passwordMatch) {
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

    // 2. Check Teachers
    query = 'SELECT * FROM teacher WHERE ';
    if (loginType === 'email') {
      query += 'LOWER(personal_email) = ?';
    } else {
      query += 'LOWER(username) = ?';
    }

    const [teachers] = await promisePool.query(query, [sanitizedInput]);
    console.log('Teacher check:', { found: teachers.length > 0 });

    if (teachers.length > 0) {
      const teacher = teachers[0];
      const passwordMatch = await bcrypt.compare(password, teacher.password);
      console.log('Stored hashed password:', teacher.password);
      console.log('Attempting to match with provided password:', password);
      console.log('Teacher password check:', { matches: passwordMatch });
      console.log('Password match result:', passwordMatch);
      if (passwordMatch) {
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

    // 3. Check Admin
    query = 'SELECT * FROM admin WHERE LOWER(username) = ?';
    const [admins] = await promisePool.query(query, [sanitizedInput]);
    console.log('Admin check:', { found: admins.length > 0 });

    if (admins.length > 0) {
      const admin = admins[0];
      const passwordMatch = await bcrypt.compare(password, admin.password);

      console.log('Admin password check:', { matches: passwordMatch });

      if (passwordMatch) {
        return res.json({
          success: true,
          user: {
            username: admin.username,
            role: 'admin'
          }
        });
      }
    }

    // No matching user found or password incorrect
    let errorMessage = 'Invalid credentials';

    // More specific error messages based on what we found
    if (students.length > 0 || teachers.length > 0 || admins.length > 0) {
      errorMessage = 'Incorrect password';
    } else {
      errorMessage = loginType === 'email' 
        ? 'No account found with this email address'
        : 'No account found with this username';
    }

    return res.status(401).json({
      success: false,
      message: errorMessage
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during login'
    });
  }
};

const handleRegister = async (data, res) => {
  const { studentId, firstName, middleName, lastName, course, section, academic_term } = data;
  const fullName = middleName ? `${firstName} ${middleName} ${lastName}` : `${firstName} ${lastName}`;
  const username = generateStudent(firstName, lastName, studentId);
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
  await promisePool.query(
    'INSERT INTO students SET ?',
    {
      student_id: studentId,
      first_name: firstName,
      middle_name: middleName,
      last_name: lastName,
      full_name: fullName,
      course,
      section,
      trimester: academic_term,
      email: data.email,
      username,
      password: hashedPassword
    }
  );

  res.json({ success: true, credentials: { username, password: plainPassword } });
};

const handleTeacherRegister = async (data, res) => {
  const { teacher_id, teacher_name, personal_email } = data;

  try {
    // Check if teacher already exists
    const [existing] = await promisePool.query(
      'SELECT 1 FROM teacher WHERE teacher_id = ? OR personal_email = ?',
      [teacher_id, personal_email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Teacher with this ID or email already exists' 
      });
    }

    // Generate credentials using the updated function
    const username = generateTeacher(teacher_name, teacher_id);
    const password = generatePassword();
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log('Hashed password:', hashedPassword);
    console.log('Generated password:', password);

    // Insert teacher
    await promisePool.query(
      'INSERT INTO teacher (teacher_id, teacher_name, personal_email, username, password) VALUES (?, ?, ?, ?, ?)',
      [teacher_id, teacher_name, personal_email, username, hashedPassword]
    );

    res.json({
      success: true,
      message: 'Teacher registered successfully',
      credentials: { username, password }
    });
  } catch (error) {
    console.error('Error registering teacher:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
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

const handleDeleteTeacher = async (data, res) => {
  const { teacherId } = data;

  try {
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
    // If studentId is provided, return specific student data
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

    // Get students, teachers, and grades data for admin dashboard
    const [students] = await promisePool.query(
      'SELECT student_id, full_name, password, course FROM students'
    );
    
    const [teachers] = await promisePool.query(
      'SELECT teacher_id, teacher_name, personal_email, password, username FROM teacher'
    );
    
    const [grades] = await promisePool.query(
      'SELECT * FROM grades'
    );

    // If specific data type is requested
    if (data.dataType) {
      switch (data.dataType) {
        case 'students':
          return res.json({ success: true, students });
        case 'teachers':
          return res.json({ success: true, teachers });
        case 'grades':
          return res.json({ success: true, grades });
        default:
          return res.status(400).json({ success: false, message: 'Invalid data type requested' });
      }
    }

    // Return all data if no specific type is requested
    res.json({ 
      success: true, 
      students,
      teachers,
      grades
    });
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Batch size for processing records
const BATCH_SIZE = 50;

// ENDPOINT 2: Grades Management
router.all('/grades', upload.single('file'), async (req, res) => {
  // Set CORS headers for every request
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const [columns] = await promisePool.query(`
      SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'grades'
      ORDER BY ORDINAL_POSITION;
    `);

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
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  const results = [];
  const errors = [];
  const columnNames = columns.map(col => col.COLUMN_NAME.toLowerCase());
  let processedCount = 0;

  try {
    // Create a readable stream from the buffer
    const bufferStream = new require('stream').Readable();
    bufferStream.push(req.file.buffer);
    bufferStream.push(null);

    // Process CSV data
    await new Promise((resolve, reject) => {
      bufferStream
        .pipe(csv())
        .on('data', (row) => {
          try {
            const transformedRow = processRow(row, columnNames);
            results.push(transformedRow);
          } catch (error) {
            errors.push({ row, error: error.message });
          }
        })
        .on('end', resolve)
        .on('error', reject);
    });

    // Process in batches
    for (let i = 0; i < results.length; i += BATCH_SIZE) {
      const batch = results.slice(i, i + BATCH_SIZE);
      await processBatch(batch);
      processedCount += batch.length;

      // Optional: Send progress updates
      if (req.socket.writable) {
        res.write(JSON.stringify({
          type: 'progress',
          processed: processedCount,
          total: results.length
        }) + '\n');
      }
    }

    // Send final response
    res.json({
      success: true,
      count: processedCount,
      errors: errors.length > 0 ? errors : undefined,
      tableInfo: {
        columnCount: columns.length,
        columns: columns.map(col => col.COLUMN_NAME)
      }
    });
  } catch (error) {
    console.error('Error processing grades:', error);
    res.status(500).json({
      success: false,
      message: 'Error processing grades',
      error: error.message
    });
  }
};

// Helper function to process individual rows
const processRow = (row, columnNames) => {
  const transformedRow = {};
  
  Object.entries(row).forEach(([key, value]) => {
    const normalizedKey = key.toLowerCase();
    if (columnNames.includes(normalizedKey)) {
      transformedRow[normalizedKey] = value;
    }
  });

  // Calculate grades
  const prelim = parseFloat(row.PRELIM_GRADE) || 0;
  const midterm = parseFloat(row.MIDTERM_GRADE) || 0;
  const final = parseFloat(row.FINAL_GRADE) || 0;
  const gwa = (prelim + midterm + final) / 3;

  transformedRow.gwa = gwa.toFixed(2);
  transformedRow.remark = midterm && final ? 
    (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC';

  return transformedRow;
};

// Helper function to process batches of records
const processBatch = async (batch) => {
  const connection = await promisePool.getConnection();
  try {
    await connection.beginTransaction();

    for (const row of batch) {
      await connection.query(
        'INSERT INTO grades SET ? ON DUPLICATE KEY UPDATE ?',
        [row, row]
      );
    }

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
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

// ENDPOINT 4: File Upload
router.get('/teachers', async (req, res) => {
  try {
    const [teachers] = await promisePool.query(
      'SELECT teacher_id, teacher_name, personal_email, username FROM teacher'
    );
    res.json({ success: true, teachers });
  } catch (error) {
    console.error('Error fetching teachers:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/teachers', async (req, res) => {
  try {
    const { teacher_id, teacher_name, personal_email, username, password } = req.body;

    // Check if teacher already exists
    const [existing] = await promisePool.query(
      'SELECT 1 FROM teacher WHERE teacher_id = ? OR personal_email = ? OR username = ?',
      [teacher_id, personal_email, username]
    );

    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Teacher with this ID, email, or username already exists' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await promisePool.query(
      'INSERT INTO teacher (teacher_id, teacher_name, personal_email, username, password) VALUES (?, ?, ?, ?, ?)',
      [teacher_id, teacher_name, personal_email, username, hashedPassword]
    );

    res.json({ success: true, message: 'Teacher added successfully' });
  } catch (error) {
    console.error('Error adding teacher:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.delete('/teachers/:teacherId', async (req, res) => {
  try {
    const { teacherId } = req.params;

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
