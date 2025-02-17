
const express = require('express');
const cors = require('cors')
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const jwt_secret_key = process.env.JWT_SECRET || 'your_secret_key_here'

app.use(cors({
    origin: ['http://localhost:3000', 'https://your-frontend-domain.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const dbPath = path.join(__dirname, 'notes.db');
let db;

const authenticateToken = (request, response, next) => {
    const authHeader = request.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return response.status(401).json({ error: 'Authentication required' })
    }

    try {
        const user = jwt.verify(token, jwt_secret_key)
        request.user = user
        next()
    } catch (error) {
        return response.status(403).json({ error: 'Invalid token' })
    }
}

const initializeDbAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });

        await db.exec(`
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                password TEXT
            );
            
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                content TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES user (id)
            );
        `);

        const PORT = process.env.PORT || 5000;
        app.listen(PORT, () => {
            console.log(`Server Running on port ${PORT}`);
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDbAndServer();

// Routes
app.post('/signup', async(request, response) => {
    try {
        const { name, email, password } = request.body
        
        const existingUser = await db.get('SELECT * FROM user WHERE email = ?', [email])
        if (existingUser) {
            return response.status(400).json({ error: 'Email already exists' })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashedPassword = await bcryptjs.hash(password, salt)
        
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

app.post('/login', async (request, response) => {
    try {
        const { email, password } = request.body
        
        const user = await db.get('SELECT * FROM user WHERE email = ?', [email])
        if (!user) {
            return response.status(400).json({ error: 'Invalid email' })
        }

        const validPassword = await bcryptjs.compare(password, user.password)
        if (!validPassword) {
            return response.status(400).json({ error: 'Invalid password' })
        }

        const token = jwt.sign(
            { userId: user.id },
            jwt_secret_key,
            { expiresIn: '30d' }
        )
        
        response.json({ token })
    } catch (error) {
        console.error('Login error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

app.get('/notes', authenticateToken, async (request, response) => {
    try {
        const { userId } = request.user
        const notes = await db.all(
            'SELECT * FROM notes WHERE user_id = ?',
            [userId]
        )
        response.json(notes)
    } catch (error) {
        console.error('Get notes error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

app.get('/notes/:id', authenticateToken, async(request, response) => {
    try {
        const { id } = request.params
        const { userId } = request.user
        const note = await db.get(
            'SELECT * FROM notes WHERE id = ? AND user_id = ?',
            [id, userId]
        )
        if (!note) {
            return response.status(404).json({ error: 'Note not found' })
        }
        response.json(note)
    } catch (error) {
        console.error('Get note error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

app.post('/notes', authenticateToken, async(request, response) => {
    try {
        const { title, content } = request.body
        const { userId } = request.user
        
        const result = await db.run(
            'INSERT INTO notes(title, content, user_id) VALUES(?, ?, ?)',
            [title, content, userId]
        )
        
        response.status(201).json({
            message: 'Note created successfully',
            noteId: result.lastID
        })
    } catch (error) {
        console.error('Create note error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

app.put('/notes/:id', authenticateToken, async(request, response) => {
    try {
        const { title, content } = request.body
        const { id } = request.params
        const { userId } = request.user

        const result = await db.run(
            'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?',
            [title, content, id, userId]
        )

        if (result.changes === 0) {
            return response.status(404).json({ error: 'Note not found' })
        }

        response.json({ message: 'Note updated successfully' })
    } catch (error) {
        console.error('Update note error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})

app.delete('/notes/:id', authenticateToken, async(request, response) => {
    try {
        const { id } = request.params
        const { userId } = request.user

        const result = await db.run(
            'DELETE FROM notes WHERE id = ? AND user_id = ?',
            [id, userId]
        )

        if (result.changes === 0) {
            return response.status(404).json({ error: 'Note not found' })
        }

        response.json({ message: 'Note deleted successfully' })
    } catch (error) {
        console.error('Delete note error:', error)
        response.status(500).json({ error: 'Internal server error' })
    }
})
