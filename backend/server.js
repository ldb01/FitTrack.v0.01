const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);




const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');

require('dotenv').config();

const app = express();

app.use(express.json());

app.use(session({
    store: new pgSession({
        pool: db,
        createTableIfMissing: true
    }),

    secret: process.env.SESSION_SECRET,

    resave: false,
    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

// Homepage
app.get('/', (req, res) => {
    res.send('FitTrack Backend is running!');
});

// Database test
app.get('/api/test-db', async (req, res) => {
    try {
        const result = await db.query('SELECT NOW()');

        res.json({
            message: 'Database connected successfully!',
            time: result.rows[0].now
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'Database connection failed'
        });
    }
});

// USER REGISTRATION
app.post('/api/auth/register', async (req, res) => {

    try {
        // 1. Get information from signup form
        const { name, username, email, password } = req.body;

        // 2. Validate input
        if (!name || !username || !email || !password) {
            return res.status(400).json({
                message: 'All fields are required'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters'
            });
        }

        // 3. Normalize input
        const cleanName = name.trim();
        const cleanUsername = username.trim().toLowerCase();
        const cleanEmail = email.trim().toLowerCase();

        if (!cleanName || !cleanUsername || !cleanEmail) {
            return res.status(400).json({
                message: 'Fields cannot contain only spaces'
            });
        }

        if (!/^[a-z0-9_]{3,30}$/.test(cleanUsername)) {
            return res.status(400).json({
                message: 'Username must be 3-30 characters and contain only letters, numbers or underscores'
            });
        }

        // 4. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 5. Insert user into PostgreSQL
        const result = await db.query(
            `INSERT INTO users (name, username, email, password_hash)
             VALUES ($1, $2, $3, $4)
             RETURNING id, name, username, email, created_at`,
            [cleanName, cleanUsername, cleanEmail, hashedPassword]
        );

        // 6. Send successful response
        res.status(201).json({
            message: 'Account created successfully!',
            user: result.rows[0]
        });

    } catch (error) {

        // Duplicate username or email
        if (error.code === '23505') {
            return res.status(409).json({
                message: 'Username or email already exists'
            });
        }

        console.error(error);

        res.status(500).json({
            message: 'Something went wrong during registration'
        });
    }
});

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`FitTrack server running on port ${PORT}`);
});


// USER LOGIN
app.post('/api/auth/login', async (req, res) => {

    try {
        // 1. Get login information
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: 'Email and password are required'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // 2. Find user in database
        const result = await db.query(
            'SELECT * FROM users WHERE email = $1',
            [cleanEmail]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        const user = result.rows[0];

        // 3. Compare submitted password with stored hash
        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        // 4. Regenerate session to prevent session fixation
        req.session.regenerate((err) => {

            if (err) {
                console.error(err);

                return res.status(500).json({
                    message: 'Could not create login session'
                });
            }

            // 5. Store user ID in session
            req.session.userId = user.id;

            // 6. Save session
            req.session.save((err) => {

                if (err) {
                    console.error(err);

                    return res.status(500).json({
                        message: 'Could not save login session'
                    });
                }

                res.json({
                    message: 'Login successful!',
                    user: {
                        id: user.id,
                        name: user.name,
                        username: user.username,
                        email: user.email
                    }
                });
            });
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Something went wrong during login'
        });
    }
});


// CHECK LOGGED-IN USER
app.get('/api/auth/me', async (req, res) => {

    if (!req.session.userId) {
        return res.status(401).json({
            message: 'Not logged in'
        });
    }

    try {
        const result = await db.query(
            `SELECT id, name, username, email
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                message: 'User not found'
            });
        }

        res.json({
            loggedIn: true,
            user: result.rows[0]
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Server error'
        });
    }
});


// USER LOGOUT
app.post('/api/auth/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            return res.status(500).json({
                message: 'Could not log out'
            });
        }

        res.clearCookie('connect.sid');

        res.json({
            message: 'Logged out successfully'
        });
    });
});