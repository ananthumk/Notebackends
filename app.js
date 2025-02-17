const express = require('express');
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express();

const jwt_secret_key = 'secret_key'

// Update CORS configuration
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'notes.db');

let db;

// ... authentication middleware remains the same ...

const initialDbandServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });
        // Change the port to 5000 or another available port
        app.listen(5000, () => {
            console.log(`Server Running at http://localhost:5000/`);
        });
    } catch (e) {
        console.log(`Error Message: ${e.message}`);
        process.exit(1);
    }
};

initialDbandServer();

// Fix the login endpoint
app.post('/login', async (request, response) => {
    try {
        const { email, password } = request.body;
        
        // Fix the SQL query and await it
        const userDetails = await db.get(`SELECT * FROM user WHERE email = ?`, [email]);
        
        if (!userDetails) {
            return response.status(400).json({ error: 'Invalid email' });
        }

        const validPassword = await bcrypt.compare(password, userDetails.password);
        if (!validPassword) {
            return response.status(400).json({ error: 'Invalid Password' });
        }

        const token = jwt.sign(
            { userId: userDetails.id }, 
            jwt_secret_key, 
            { expiresIn: '30d' }
        );
        
        response.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        response.status(500).json({ error: 'Internal server error' });
    }
});

// ... rest of your endpoints remain the same ...

module.exports = app;
