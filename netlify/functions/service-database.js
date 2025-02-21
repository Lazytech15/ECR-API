import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import csv from 'csv-parser';
import nodemailer from 'nodemailer';
import serverless from 'serverless-http';
import multer from 'multer';

// Logger utility function
const logRequest = (endpoint, action, details) => {
  const timestamp = new Date().toISOString();
  console.log(JSON.stringify({
    timestamp,
    endpoint,
    action,
    ...details
  }));
};

const logError = (endpoint, action, error, details = {}) => {
  const timestamp = new Date().toISOString();
  console.error(JSON.stringify({
    timestamp,
    endpoint,
    action,
    error: error.message,
    stack: error.stack,
    ...details
  }));
};

const app = express();
const router = express.Router();

// Configure CORS
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5173',
  'http://localhost:5500',
  'http://localhost:5173',
  'http://localhost:3000',
  'https://mailer.cyberdyne.top',
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
      case 'delete-batch-student':
        await handleBatchDeleteStudents(data, res);
        break;
      case 'delete-teacher':   // Add teacher deletion
        await handleDeleteTeacher(data, res);
        break;
      case 'delete-batch-teacher':   // Add teacher deletion
        await handleBatchDeleteTeachers(data, res);
        break;
      case 'delete-grade':
        await handleDeleteGrade(req.body, res);
        break;
      case 'delete-multiple-grades':
        await handleDeleteMultipleGrades(req.body, res);
        break;
      case 'get-alldata':
        await handleGetAllData(data, res);
        break;
      case 'update-student':
        await handleUpdateStudent(data, res);
        break;
      case 'update-teacher':
        await handleUpdateTeacher(data, res);
        break;
      case 'update-grade':
        await handleUpdateGrade(data, res);
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

const handleBatchDeleteStudents = async (data, res) => {
  const { studentIds } = data;
  
  try {
    // Use transaction to ensure all deletions succeed or none do
    await promisePool.query('START TRANSACTION');
    
    for (const studentId of studentIds) {
      await promisePool.query(
        'DELETE FROM students WHERE student_id = ?',
        [studentId]
      );
    }
    
    await promisePool.query('COMMIT');
    
    res.json({
      success: true,
      message: `Successfully deleted ${studentIds.length} students`
    });
  } catch (error) {
    await promisePool.query('ROLLBACK');
    console.error('Error in batch delete students:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting students'
    });
  }
};

const handleBatchDeleteTeachers = async (data, res) => {
  const { teacherIds } = data;
  
  try {
    // Use transaction to ensure all deletions succeed or none do
    await promisePool.query('START TRANSACTION');
    
    for (const teacherId of teacherIds) {
      await promisePool.query(
        'DELETE FROM teacher WHERE teacher_id = ?',
        [teacherId]
      );
    }
    
    await promisePool.query('COMMIT');
    
    res.json({
      success: true,
      message: `Successfully deleted ${teacherIds.length} teachers`
    });
  } catch (error) {
    await promisePool.query('ROLLBACK');
    console.error('Error in batch delete teachers:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting teachers'
    });
  }
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
  const { ecr_name: deleteEcrName, student_num: studentNum, course_code: courseCode } = data;

  try {
    // First try to find by ecr_name
    let gradeToDelete;
    if (deleteEcrName) {
      [gradeToDelete] = await promisePool.query(
        'SELECT * FROM grades WHERE ecr_name = ?',
        [deleteEcrName]
      );
    }

    // If not found by ecr_name, try student_num and course_code
    if (!gradeToDelete || gradeToDelete.length === 0) {
      [gradeToDelete] = await promisePool.query(
        'SELECT * FROM grades WHERE student_num = ? AND course_code = ?',
        [studentNum, courseCode]
      );
    }

    if (!gradeToDelete || gradeToDelete.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Grade entry not found' 
      });
    }

    // Delete using the found record's criteria
    if (deleteEcrName) {
      await promisePool.query(
        'DELETE FROM grades WHERE ecr_name = ?',
        [deleteEcrName]
      );
    } else {
      await promisePool.query(
        'DELETE FROM grades WHERE student_num = ? AND course_code = ?',
        [studentNum, courseCode]
      );
    }

    res.json({
      success: true,
      message: 'Grade entry deleted successfully',
      deletedGrade: gradeToDelete[0]
    });

  } catch (error) {
    console.error('Error deleting grade:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting grade entry',
      error: error.message
    });
  }
};

const handleDeleteMultipleGrades = async (data, res) => {
  const { grades } = data;
  
  try {
    const results = [];
    const errors = [];

    // Process each grade deletion
    for (const grade of grades) {
      try {
        // Always try ecr_name first if available
        if (grade.ecr_name) {
          const [deleteResult] = await promisePool.query(
            'DELETE FROM grades WHERE ecr_name = ?',
            [grade.ecr_name]
          );

          if (deleteResult.affectedRows > 0) {
            results.push({
              success: true,
              grade: grade
            });
            continue;
          }
        }

        // Fallback to using student_num and course_code
        const [deleteResult] = await promisePool.query(
          'DELETE FROM grades WHERE student_num = ? AND course_code = ?',
          [grade.student_num, grade.course_code]
        );

        if (deleteResult.affectedRows > 0) {
          results.push({
            success: true,
            grade: grade
          });
        } else {
          errors.push({
            grade,
            message: 'Grade entry not found'
          });
        }

      } catch (error) {
        console.error('Error deleting grade:', error);
        errors.push({
          grade,
          message: error.message
        });
      }
    }

    res.json({
      success: true,
      message: 'Batch deletion completed',
      results: {
        successful: results,
        failed: errors,
        totalProcessed: grades.length,
        successCount: results.length,
        failureCount: errors.length
      }
    });

  } catch (error) {
    console.error('Error in batch deletion:', error);
    res.status(500).json({
      success: false,
      message: 'Error processing batch deletion',
      error: error.message
    });
  }
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
    'SELECT student_id, full_name, course, section, trimester, email, username, password FROM students'
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

const handleUpdateStudent = async (data, res) => {
  try {
    const { 
      studentId, 
      currentPassword,
      newPassword,
      newSection,
      newTrimester, 
      newEmail,
      newCourse 
    } = data;

    // First verify the student exists
    const [student] = await promisePool.query(
      'SELECT password FROM students WHERE student_id = ?',
      [studentId]
    );

    if (!student.length) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    // Verify current password if changing password
    if (currentPassword) {
      const validPassword = await bcrypt.compare(currentPassword, student[0].password);
      if (!validPassword) {
        return res.status(400).json({ success: false, message: 'Invalid current password' });
      }
    }

    // Build update object
    const updates = {};
    if (newPassword) {
      updates.password = await bcrypt.hash(newPassword, 10);
    }
    if (newSection) updates.section = newSection;
    if (newTrimester) updates.trimester = newTrimester;
    if (newEmail) updates.email = newEmail;
    if (newCourse) updates.course = newCourse;

    // Only proceed if there are updates
    if (Object.keys(updates).length === 0) {
      return res.json({ success: true, message: 'No changes requested' });
    }

    const [result] = await promisePool.query(
      'UPDATE students SET ? WHERE student_id = ?',
      [updates, studentId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Update failed' });
    }

    res.json({ 
      success: true, 
      message: 'Student updated successfully',
      updatedFields: Object.keys(updates)
    });
  } catch (error) {
    console.error('Error updating student:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const handleUpdateTeacher = async (data, res) => {
  try {
    const { teacherId, teacherName, personalEmail } = data;

    // Validate required field
    if (!teacherId) {
      return res.status(400).json({ success: false, message: 'Teacher ID is required' });
    }

    // Build update object
    const updates = {};
    if (teacherName) updates.teacher_name = teacherName;
    if (personalEmail) updates.personal_email = personalEmail;

    // Only proceed if there are updates
    if (Object.keys(updates).length === 0) {
      return res.json({ success: true, message: 'No changes requested' });
    }

    const [result] = await promisePool.query(
      'UPDATE teacher SET ? WHERE teacher_id = ?',
      [updates, teacherId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Teacher not found' });
    }

    res.json({ 
      success: true, 
      message: 'Teacher updated successfully',
      updatedFields: Object.keys(updates)
    });
  } catch (error) {
    console.error('Error updating teacher:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const handleUpdateGrade = async (data, res) => {
  try {
    const { 
      ecrName,
      studentNum,
      courseCode,
      prelimGrade,
      midtermGrade,
      finalGrade,
      remark
    } = data;

    // Validate required fields
    if (!studentNum || !courseCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Student number and course code are required' 
      });
    }

    // Build update object
    const updates = {};
    if (prelimGrade !== undefined) updates.prelim_grade = prelimGrade;
    if (midtermGrade !== undefined) updates.midterm_grade = midtermGrade;
    if (finalGrade !== undefined) updates.final_grade = finalGrade;
    if (remark !== undefined) updates.remark = remark;

    // Calculate GWA if grades are provided
    if (prelimGrade !== undefined || midtermGrade !== undefined || finalGrade !== undefined) {
      const [currentGrades] = await promisePool.query(
        'SELECT prelim_grade, midterm_grade, final_grade FROM grades WHERE student_num = ? AND course_code = ?',
        [studentNum, courseCode]
      );

      const grades = currentGrades[0] || {};
      const prelim = prelimGrade ?? grades.prelim_grade ?? 0;
      const midterm = midtermGrade ?? grades.midterm_grade ?? 0;
      const final = finalGrade ?? grades.final_grade ?? 0;
      
      updates.gwa = ((prelim + midterm + final) / 3).toFixed(2);
      
      // Update remark based on grades if not explicitly provided
      if (remark === undefined) {
        updates.remark = midterm && final ? 
          (updates.gwa <= 3.00 ? 'PASSED' : 'FAILED') : 
          'INC';
      }
    }

    // Only proceed if there are updates
    if (Object.keys(updates).length === 0) {
      return res.json({ success: true, message: 'No changes requested' });
    }

    const [result] = await promisePool.query(
      'UPDATE grades SET ? WHERE student_num = ? AND course_code = ?',
      [updates, studentNum, courseCode]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Grade record not found' });
    }

    res.json({ 
      success: true, 
      message: 'Grade updated successfully',
      updatedFields: Object.keys(updates)
    });
  } catch (error) {
    console.error('Error updating grade:', error);
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
      if (req.file) {
        await handleBatchUpload(req, res, columns);
      } else {
        await handleSingleGradeUpload(req, res, columns);
      }
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

  logRequest('grades', 'fetch-request', { 
    teacherId, 
    studentId,
    schemaRequest: req.query.schema === 'true' 
  });

  try {
    if (req.query.schema === 'true') {
      logRequest('grades', 'schema-fetch', { 
        columnCount: columns.length 
      });
      
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
    
    logRequest('grades', 'fetch-success', { 
      recordCount: grades.length,
      queryType: teacherId ? 'teacher' : 'student'
    });

    res.json({ success: true, grades });
  } catch (error) {
    logError('grades', 'fetch', error, { 
      teacherId, 
      studentId 
    });
    
    res.status(500).json({
      success: false,
      message: 'Error fetching grades',
      error: error.message
    });
  }
};

const handleSingleGradeUpload = async (req, res, columns) => {
  try {
    const columnNames = columns.map(col => col.COLUMN_NAME.toLowerCase());
    
    // Transform form data to match database columns
    const gradeData = {};
    for (const [key, value] of Object.entries(req.body)) {
      const normalizedKey = key.toLowerCase();
      if (columnNames.includes(normalizedKey)) {
        gradeData[normalizedKey] = value;
      }
    }

    // Calculate GWA and remark if not provided
    if (!gradeData.gwa || !gradeData.remark) {
      const prelim = parseFloat(gradeData.prelim_grade) || 0;
      const midterm = parseFloat(gradeData.midterm_grade) || 0;
      const final = parseFloat(gradeData.final_grade) || 0;
      const gwa = (prelim + midterm + final) / 3;

      gradeData.gwa = gwa.toFixed(2);
      gradeData.remark = midterm && final ?
        (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC';
    }

    // Insert or update the grade
    await promisePool.query(
      'INSERT INTO grades SET ? ON DUPLICATE KEY UPDATE ?',
      [gradeData, gradeData]
    );

    res.json({
      success: true,
      message: 'Grade uploaded successfully',
      data: gradeData
    });

  } catch (error) {
    console.error('Single grade upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Error uploading grade',
      error: error.message
    });
  }
};

const handleBatchUpload = async (req, res, columns) => {
  if (!req.file) {
    logRequest('grades', 'batch-upload-failed', { 
      reason: 'No file provided' 
    });
    
    return res.status(400).json({ 
      success: false, 
      message: 'No file uploaded' 
    });
  }

  const batchSize = parseInt(req.query.batchSize) || 5;
  
  logRequest('grades', 'batch-upload-start', { 
    fileSize: req.file.size,
    batchSize
  });

  try {
    // Create a readable stream from the buffer
    const bufferStream = new require('stream').Readable();
    bufferStream.push(req.file.buffer);
    bufferStream.push(null);

    let batch = [];
    let isFirstRow = true;

    await new Promise((resolve, reject) => {
      bufferStream
        .pipe(csv())
        .on('data', async (row) => {
          // Skip header row
          if (isFirstRow) {
            isFirstRow = false;
            return;
          }

          results.total++;

          try {
            // Transform row keys to match database column names
            const transformedRow = {};
            Object.entries(row).forEach(([key, value]) => {
              const normalizedKey = key.toLowerCase();
              if (columnNames.includes(normalizedKey)) {
                transformedRow[normalizedKey] = value;
              }
            });

            // Calculate GWA and remark
            const prelim = parseFloat(row.PRELIM_GRADE) || 0;
            const midterm = parseFloat(row.MIDTERM_GRADE) || 0;
            const final = parseFloat(row.FINAL_GRADE) || 0;
            const gwa = (prelim + midterm + final) / 3;

            transformedRow.gwa = gwa.toFixed(2);
            transformedRow.remark = midterm && final ?
              (gwa <= 3.00 ? 'PASSED' : 'FAILED') : 'INC';

            batch.push(transformedRow);

            // Process batch when it reaches the specified size
            if (batch.length >= batchSize) {
              await processBatch(batch, results);
              batch = [];
            }
          } catch (error) {
            results.failed.push({
              row: row,
              error: error.message
            });
          }
        })
        .on('end', async () => {
          // Process remaining records in the last batch
          if (batch.length > 0) {
            await processBatch(batch, results);
          }
          resolve();
        })
        .on('error', reject);
    });

    logRequest('grades', 'batch-upload-complete', {
      totalRecords: results.total,
      successfulUploads: results.successful.length,
      failedUploads: results.failed.length
    });

    res.json({
      success: true,
      results: {
        total: results.total,
        processed: results.processed,
        successful: results.successful.length,
        failed: results.failed,
        message: `Successfully processed ${results.successful.length} out of ${results.total} records`
      }
    });

  } catch (error) {
    console.error('Batch upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Error processing batch upload',
      error: error.message
    });
  }
};

const processBatch = async (batch, results) => {
  try {
    // Use transaction for batch processing
    const connection = await promisePool.getConnection();
    await connection.beginTransaction();

    try {
      for (const row of batch) {
        await connection.query(
          'INSERT INTO grades SET ? ON DUPLICATE KEY UPDATE ?',
          [row, row]
        );
        results.successful.push(row);
        results.processed++;
      }

      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error processing batch:', error);
    batch.forEach(row => {
      results.failed.push({
        row: row,
        error: error.message
      });
    });
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

// Mount all routes under /.netlify/functions/service-database
app.use('/.netlify/functions/service-database', router);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// Add logging to error handling middleware
app.use((err, req, res, next) => {
  logError('global', 'middleware', err, {
    path: req.path,
    method: req.method,
    query: req.query,
    body: req.body
  });
  
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// Add logging to graceful shutdown
process.on('SIGINT', async () => {
  try {
    await pool.end();
    logRequest('system', 'shutdown', { 
      status: 'success' 
    });
    process.exit(0);
  } catch (err) {
    logError('system', 'shutdown', err);
    process.exit(1);
  }
});

// Export handler for Netlify Functions
export const handler = serverless(app);
