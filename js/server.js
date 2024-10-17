const express = require('express');
const mysql = require('mysql');
const argon2 = require('argon2');
const crypto = require('crypto');
const validator = require('validator');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const Recaptcha = require('express-recaptcha').RecaptchaV2;

// Create an express app
const app = express();

// reCAPTCHA settings (replace with your actual site and secret keys)
const recaptcha = new Recaptcha('SITE_KEY', 'SECRET_KEY');

// JWT secret key
const secretKey = 'your_secret_key';

// MySQL connection settings
const dbHost = 'your_host';
const dbUser = 'your_username';
const dbPassword = 'your_password';
const dbName = 'your_database';

// Create a MySQL connection pool
const pool = mysql.createPool({
  host: dbHost,
  user: dbUser,
  password: dbPassword,
  database: dbName
});

// Argon2 settings for hashing passwords
const argon2Options = {
  type: argon2.argon2id,
  memoryCost: 2048,
  parallelism: 2
};

// Input validation middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const validateInput = (req, res, next) => {
  const { name, email, phone, password, confirmPassword } = req.body;

  if (!validator.isEmail(email)) {
    return res.status(400).send({ message: 'Invalid email address' });
  }

  if (!validator.isMobilePhone(phone, 'en-US')) {
    return res.status(400).send({ message: 'Invalid phone number' });
  }

  if (password.length < 6) {
    return res.status(400).send({ message: 'Password must be at least 6 characters long' });
  }

  if (password !== confirmPassword) {
    return res.status(400).send({ message: 'Passwords do not match' });
  }

  next();
};

// Register route
app.post('/register', validateInput, (req, res) => {
  const { name, email, phone, password } = req.body;

  // Generate a salt
  const salt = crypto.randomBytes(16);

  // Hash the password using Argon2
  argon2.hash(password, { ...argon2Options, salt })
    .then(hashedPassword => {
      // Insert the user into the database with a default role (e.g., user)
      const query = `INSERT INTO users (name, email, phone, password, salt, role) VALUES (?, ?, ?, ?, ?, 'user')`;
      const values = [name, email, phone, hashedPassword, salt.toString('hex')];

      pool.query(query, values, (err, results) => {
        if (err) {
          console.error(err);
          res.status(500).send({ message: 'Error registering user' });
        } else {
          res.send({ message: 'User registered successfully' });
        }
      });
    })
    .catch(err => {
      console.error(err);
      res.status(500).send({ message: 'Error hashing password' });
    });
});

// OTP map to store OTP temporarily
const otpMap = new Map();

// Login route with CAPTCHA and OTP
app.post('/login', recaptcha.middleware.verify, (req, res) => {
  if (!req.recaptcha.error) {
    const { email, password } = req.body;

    // Query the database to retrieve the user's salt and hashed password
    const query = `SELECT salt, password, role FROM users WHERE email = ?`;
    const values = [email];

    pool.query(query, values, (err, results) => {
      if (err) {
        console.error(err);
        res.status(500).send({ message: 'Error retrieving user' });
      } else if (results.length === 0) {
        res.status(401).send({ message: 'Invalid email or password' });
      } else {
        const { salt, password: hashedPassword, role } = results[0];

        // Hash the provided password using Argon2 with the stored salt
        argon2.hash(password, { ...argon2Options, salt: Buffer.from(salt, 'hex') })
          .then(hashedInputPassword => {
            // Verify if the hashed input password matches the stored hashed password
            if (argon2.verify(hashedPassword, hashedInputPassword)) {
              // Generate and send OTP
              const otp = crypto.randomInt(100000, 999999);
              otpMap.set(email, otp); // Store OTP temporarily

              // Send OTP to user's email
              const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: 'your_email', pass: 'your_password' } });
              const mailOptions = { from: 'your_email', to: email, subject: 'Your OTP', text: `Your OTP is ${otp}` };

              transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                  return res.status(500).send({ message: 'Error sending OTP' });
                } else {
                  res.send({ message: 'OTP sent to your email' });
                }
              });
            } else {
              res.status(401).send({ message: 'Invalid email or password' });
            }
          })
          .catch(err => {
            console.error(err);
            res.status(500).send({ message: 'Error hashing password' });
          });
      }
    });
  } else {
    res.status(400).send({ message: 'Invalid CAPTCHA' });
  }
});

// OTP verification route
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (otpMap.get(email) === parseInt(otp)) {
    otpMap.delete(email); // OTP is used once

    // Generate JWT token
    const token = jwt.sign({ email, role: 'user' }, secretKey, { expiresIn: '1h' });

    res.send({ message: 'Login successful', token });
  } else {
    res.status(401).send({ message: 'Invalid OTP' });
  }
});

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (token) {
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.status(403).send({ message: 'Forbidden' });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).send({ message: 'Unauthorized' });
  }
};

// Role-based authorization middleware
const authorize = (roles) => {
  return (req, res, next) => {
    const { role } = req.user;

    if (roles.includes(role)) {
      next();
    } else {
      res.status(403).send({ message: 'Forbidden' });
    }
  };
};

// Protected route example (only accessible by admin)
app.post('/admin-route', authenticateJWT, authorize(['admin']), (req, res) => {
  res.send({ message: 'Admin access granted' });
});

// General protected route example (accessible by any authenticated user)
app.post('/protected', authenticateJWT, (req, res) => {
  res.send({ message: 'Protected content' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send({ message: 'Internal Server Error' });
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
