// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;
const db = new sqlite3.Database(':memory:'); // In-memory database for demonstration
const SECRET_KEY = 'your_secret_key'; // Replace with your own secret key

app.use(bodyParser.json());
app.use(cors()); // Enable CORS

// Initialize the database
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS books (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, available INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, bookId INTEGER, quantity INTEGER, FOREIGN KEY(userId) REFERENCES users(id), FOREIGN KEY(bookId) REFERENCES books(id))");

    // Insert initial user credentials
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword1 = bcrypt.hashSync('password123', salt);
    const hashedPassword2 = bcrypt.hashSync('adminpassword', salt);

    db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['user1', hashedPassword1]);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', hashedPassword2]);

    // Insert initial books into the database
    db.run("INSERT INTO books (title, available) VALUES (?, ?)", ['The Great Gatsby', 10]);
    db.run("INSERT INTO books (title, available) VALUES (?, ?)", ['1984', 5]);
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) return res.status(500).send('Internal Server Error');
        if (!row || !bcrypt.compareSync(password, row.password)) return res.status(401).send('Invalid credentials');

        const token = jwt.sign({ id: row.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Request book route
app.post('/request-books', authenticateToken, (req, res) => {
    const { bookTitle, quantity } = req.body;

    db.get("SELECT id, available FROM books WHERE title = ?", [bookTitle], (err, book) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).send('Internal Server Error');
        }
        if (!book) {
            return res.status(404).send('Book not found');
        }
        if (book.available < quantity) {
            return res.status(400).send('Not enough copies available');
        }

        db.run("INSERT INTO requests (userId, bookId, quantity) VALUES (?, ?, ?)", [req.user.id, book.id, quantity], (err) => {
            if (err) {
                console.error('Database error:', err.message);
                return res.status(500).send('Internal Server Error');
            }

            db.run("UPDATE books SET available = available - ? WHERE id = ?", [quantity, book.id], (err) => {
                if (err) {
                    console.error('Database error:', err.message);
                    return res.status(500).send('Internal Server Error');
                }
                res.send('Book request successful');
            });
        });
    });
});

// Add book route
app.post('/add-book', (req, res) => {
    const { title, available } = req.body;

    db.run("INSERT INTO books (title, available) VALUES (?, ?)", [title, available], function(err) {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Book added successfully');
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

