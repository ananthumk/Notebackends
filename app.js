const express = require('express');
const cors = require('cors')
const bcrypt = require('bcryptjs')  // Changed from bcrypt to bcryptjs
const jwt = require('jsonwebtoken')
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const jwt_secret_key = process.env.JWT_SECRET || 'your_secret_key_here'

// CORS configuration
app.use(cors({
    origin: ['http://localhost:3000', 'https://your-frontend-domain.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Database setup
const dbPath = path.join(__dirname, 'notes.db');
let db;

// Rest of your code remains the same...

// Update password hashing in signup route
app.post('/signup', async(request, response) => {
    try {
        const { name, email, password } = request.body
        
        const existingUser = await db.get('SELECT * FROM user WHERE email = ?', [email])
        if (existingUser) {
            return response.status(400).json({ error: 'Email already exists' })
        }

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)
        
        await db.run(
            'INSERT INTO user(name, email, password) VALUES(?, ?, ?)',
            [name, email, hashedPassword]
        )
        
        response.status(201).json({ message: 'User created successfully' })
    } catch (error) {
        console.error('Signup error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

// Update port configuration
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server Running on port ${PORT}`);
});
