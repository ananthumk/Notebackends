const express = require('express');
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express();

const jwt_secret_key = 'secret_key'

app.use(cors());
app.use(express.json());

const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();;
const path = require('path');

const dbPath = path.join(__dirname, 'notes.db');

let db;

const authenicationToken = (request, response, next) => {
    const authHeader = request.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token){
        return response.json('Authenication required')
    }
    
    const user = jwt.verify(token , jwt_secret_key)
    request.user = user; 
    next();
}

const initialDbandServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });
        app.listen(3000, () => {
            console.log(`Server Running at http://localhost:3000/`);
        });
    } catch (e) {
        console.log(`Error Message: ${e.message}`);
        process.exit(1);
    }
};

initialDbandServer();

app.post('/signup', async(request, response) => {
    const { name, email, password} = request.body 
    const existingUser = await db.get(`SELECT * FROM user WHERE email = '${email}'`)
    if (existingUser){
       return response.json('Email already exist..')
    }

    const hashedPassword = await bcrypt.hash(password,10)
    
    const result = await db.run(`INSERT INTO user(name,email,password) VALUES('${name}', '${email}', '${hashedPassword}')`)
    response.json('Successfully user details created')

})

app.post('/login', async (request, response ) => {
    const { email, password } = request.body
    const userDetails = `SELECT * FROM user WHERE email = '${email}'`
    if (!userDetails){
        return response.json('Invalid email')
    }

    const validPassword = await bcrypt.compare(password, userDetails.password)
    if (!validPassword){
        return response.json('Invalid Password')
    }

    const token = jwt.sign({userId: user_id} , jwt_secret_key , {expires: 30})
    response.json(token)
})

app.get('/notes', authenicationToken, async (request, response) => {
        const {userId} = request.user
        const getNoteQuery = `SELECT * FROM notes where user_id =  ${userId}`;
        const notes = await db.all(getNoteQuery);
        response.json(notes);
    
});

app.get('/notes/:id', authenicationToken, async(request, response) => {
    const {id} = request.params 
    const getSpecificQuery = `
    SELECT * FROM notes WHERE id = ${id}`
    const noteQuery = await db.get(getSpecificQuery)
    response.json(noteQuery)
})

app.post('/notes' , authenicationToken, async(request, response) => {
    const {title, content} = request.body 
    const {userId} = request.user
    const createNoteQuery = `
     INSERT INTO notes( title, content , user_id) 
     VALUES( '${title}', '${content}', ${userId})
    `
    await db.run(createNoteQuery)
    response.json('Note Created SuccessFully')
})


app.put('/notes/:id' ,authenicationToken , async( request, response) => {
    const { title, content} = request.body 
    const {id} = request.params 
    const {userId} = request.user
    const updateQuery = `UPDATE notes SET 
    title = '${title}', 
    content = '${content}',
    WHERE id = ${id}, 
    AND user_id = ${userId}
    `
    response.json('Note Updated')
})



app.delete('/notes/:id',authenicationToken, async(request, response) => {
    const {id} = request.params 
    const {userId} = request.user
    const deleteQuery = `DELETE FROM notes WHERE id = ${id} AND user_id = ${userId}`
    await db.run(deleteQuery)
    response.json('Note Deleted SuccessFully')
})


module.exports = app;

