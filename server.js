require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Render / Vercel Proxy Ayarı
app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';
const PORT = process.env.PORT || 3000;

// MIDDLEWARE
app.use(helmet());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate Limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 200,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// DB CONNECTION (Aiven Cloud URI, Env Variables ve Local Uyumlu)
let dbConfig;

if (process.env.DATABASE_URL) {
    dbConfig = process.env.DATABASE_URL;
} else {
    dbConfig = {
        host: process.env.DB_HOST ? process.env.DB_HOST.trim() : 'localhost',
        user: process.env.DB_USER ? process.env.DB_USER.trim() : 'root',
        password: process.env.DB_PASS ? process.env.DB_PASS.trim() : '',
        database: process.env.DB_NAME ? process.env.DB_NAME.trim() : 'defaultdb',
        port: process.env.DB_PORT ? Number(process.env.DB_PORT.trim()) : 3306,
        ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : false,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        keepAliveInitialDelay: 0,
        connectTimeout: 60000
    };
}

const db = mysql.createPool(dbConfig);

// SSL zorunluluğunu URI/Pool tarafında garantiye alma
if (db.pool && db.pool.config && db.pool.config.connectionConfig) {
    db.pool.config.connectionConfig.ssl = { rejectUnauthorized: false };
}

// BAĞLANTI TESTİ (Render Logs ekranında görünür)
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ VERİTABANI BAĞLANTI HATASI:', err.message);
    } else {
        console.log('✅ Aiven MySQL Veritabanına Başarıyla Bağlanıldı!');
        connection.release();
    }
});

// XSS CLEANING
function cleanInput(text) {
    if (!text) return '';
    return sanitizeHtml(text, {
        allowedTags: [], 
        allowedAttributes: {}
    });
}

// JWT VERIFICATION MIDDLEWARE 
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user; // { id, role, username }
        next();
    });
}

// USER ROUTES

// SIGN UP
app.post('/api/register', async (req, res) => {
    const username = cleanInput(req.body.username);
    const email = cleanInput(req.body.email);
    const password = req.body.password;

    if (!username || !email || !password) return res.status(400).json({ error: 'Please fill in all fields.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, "user")';
        
        db.query(sql, [username, email, hashedPassword], (err, result) => {
            if (err) {
                console.error("Register SQL Error:", err);
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'This username or email is already in use.' });
                return res.status(500).json({ error: 'Database error: ' + err.message });
            }
            res.json({ message: 'Registration successful!', userId: result.insertId });
        });
    } catch (err) {
        res.status(500).json({ error: 'Encryption error.' });
    }
});

// SIGN IN
app.post('/api/login', (req, res) => {
    const email = cleanInput(req.body.email);
    const password = req.body.password;

    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const sql = 'SELECT id, username, email, password, role, profile_pic FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!results || results.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

        const user = results[0];
        let isMatch = false;

        if (user.password && user.password.startsWith('$2b$')) {
            isMatch = await bcrypt.compare(password, user.password);
        } else {
            isMatch = (password === user.password);
        }

        if (isMatch) {
            delete user.password;
            
            const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ message: 'Login successful!', user, token });
        } else {
            res.status(401).json({ error: 'Invalid email or password.' });
        }
    });
});

app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'SELECT id, username, email, role, profile_pic FROM users WHERE id = ?';
    db.query(sql, [userId], (err, results) => {
        if (err || !results || results.length === 0) return res.status(404).json({ error: 'User not found.' });
        res.json(results[0]);
    });
});

app.put('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    
    if (req.user.id != userId) return res.status(403).json({ error: 'Unauthorized.' });

    const username = cleanInput(req.body.username);
    const profile_pic = req.body.profile_pic; 

    let query = 'UPDATE users SET ';
    let queryParams = [];

    if (username && profile_pic) { query += 'username = ?, profile_pic = ? WHERE id = ?'; queryParams = [username, profile_pic, userId]; }
    else if (username) { query += 'username = ? WHERE id = ?'; queryParams = [username, userId]; }
    else if (profile_pic) { query += 'profile_pic = ? WHERE id = ?'; queryParams = [profile_pic, userId]; }
    else return res.status(400).json({ error: 'No data to update.' });

    db.query(query, queryParams, (err) => {
        if (err) return res.status(500).json({ error: 'Update error: ' + err.message });
        res.json({ message: 'Profile updated.' });
    });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    
    const isAuthorized = ['admin', 'moderator'].includes(req.user.role) || req.user.id == userId;
    if (!isAuthorized) return res.status(403).json({ error: 'Unauthorized.' });

    db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) return res.status(500).json({ error: 'Error deleting account.' });
        res.json({ message: 'Account deleted successfully.' });
    });
});

// QUOTES ROUTES

app.post('/api/quotes', authenticateToken, (req, res) => {
    const content = cleanInput(req.body.content);
    const user_id = req.user.id; 

    if (!content) return res.status(400).json({ error: 'Quote content is required.' });

    const sql = 'INSERT INTO quotes (user_id, content) VALUES (?, ?)';
    db.query(sql, [user_id, content], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Quote added successfully!', quoteId: result.insertId });
    });
});

app.get('/api/quotes', (req, res) => {
    const userId = req.query.userId || 0;

    const sql = `
        SELECT 
            quotes.id, quotes.content, quotes.created_at, quotes.user_id, users.username, users.profile_pic,
            IF(likes.id IS NOT NULL, true, false) AS is_liked,
            IF(reposts.id IS NOT NULL, true, false) AS is_reposted,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count,
            (SELECT COUNT(*) FROM comments WHERE comments.quote_id = quotes.id) AS comments_count
        FROM quotes 
        JOIN users ON quotes.user_id = users.id 
        LEFT JOIN likes ON likes.quote_id = quotes.id AND likes.user_id = ?
        LEFT JOIN reposts ON reposts.quote_id = quotes.id AND reposts.user_id = ?
        ORDER BY quotes.created_at DESC
    `;

    db.query(sql, [userId, userId], (err, results) => {
        if (err) {
            console.error("Fetch Quotes Error:", err);
            return res.json([]);
        }
        res.json(results || []);
    });
});

app.get('/api/user-quotes/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = `
        SELECT quotes.id, quotes.content, quotes.created_at, quotes.user_id, users.username, users.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count,
            (SELECT COUNT(*) FROM comments WHERE comments.quote_id = quotes.id) AS comments_count
        FROM quotes JOIN users ON quotes.user_id = users.id 
        WHERE quotes.user_id = ? ORDER BY quotes.created_at DESC
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) return res.json([]);
        res.json(results || []);
    });
});

app.get('/api/user-likes/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = `
        SELECT quotes.id, quotes.content, quotes.created_at, quotes.user_id, users.username, users.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count,
            (SELECT COUNT(*) FROM comments WHERE comments.quote_id = quotes.id) AS comments_count
        FROM likes JOIN quotes ON likes.quote_id = quotes.id JOIN users ON quotes.user_id = users.id 
        WHERE likes.user_id = ? ORDER BY likes.id DESC
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) return res.json([]);
        res.json(results || []);
    });
});

app.get('/api/user-reposts/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = `
        SELECT quotes.id, quotes.content, quotes.created_at, quotes.user_id, users.username, users.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count,
            (SELECT COUNT(*) FROM comments WHERE comments.quote_id = quotes.id) AS comments_count
        FROM reposts JOIN quotes ON reposts.quote_id = quotes.id JOIN users ON quotes.user_id = users.id 
        WHERE reposts.user_id = ? ORDER BY reposts.id DESC
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) return res.json([]);
        res.json(results || []);
    });
});

app.get('/api/user-comments/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = `
        SELECT comments.id AS comment_id, comments.content AS comment_content, comments.created_at,
               quotes.id AS quote_id, quotes.content AS quote_content, users.username, users.profile_pic 
        FROM comments JOIN quotes ON comments.quote_id = quotes.id JOIN users ON comments.user_id = users.id 
        WHERE comments.user_id = ? ORDER BY comments.created_at DESC
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) return res.json([]);
        res.json(results || []);
    });
});

app.get('/api/search', (req, res) => {
    const query = cleanInput(req.query.q || '');
    const userId = req.query.userId || 0;

    const sanitizedQuery = query.replace(/[%_]/g, '\\$&');
    const searchTerm = `%${sanitizedQuery}%`;

    const sql = `
        SELECT 
            quotes.id, quotes.content, quotes.created_at, quotes.user_id, users.username, users.profile_pic,
            IF(likes.id IS NOT NULL, true, false) AS is_liked,
            IF(reposts.id IS NOT NULL, true, false) AS is_reposted,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count,
            (SELECT COUNT(*) FROM comments WHERE comments.quote_id = quotes.id) AS comments_count
        FROM quotes JOIN users ON quotes.user_id = users.id 
        LEFT JOIN likes ON likes.quote_id = quotes.id AND likes.user_id = ?
        LEFT JOIN reposts ON reposts.quote_id = quotes.id AND reposts.user_id = ?
        WHERE quotes.content LIKE ? OR users.username LIKE ?
        ORDER BY quotes.created_at DESC
    `;
    db.query(sql, [userId, userId, searchTerm, searchTerm], (err, results) => {
        if (err) return res.json([]);
        res.json(results || []);
    });
});

// INTERACTION ROUTES

app.post('/api/quotes/:id/like', authenticateToken, (req, res) => {
    const quoteId = req.params.id;
    const user_id = req.user.id;

    db.query('SELECT * FROM likes WHERE quote_id = ? AND user_id = ?', [quoteId, user_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results && results.length > 0) {
            db.query('DELETE FROM likes WHERE quote_id = ? AND user_id = ?', [quoteId, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ liked: false });
            });
        } else {
            db.query('INSERT INTO likes (quote_id, user_id) VALUES (?, ?)', [quoteId, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ liked: true });
            });
        }
    });
});

app.post('/api/quotes/:id/repost', authenticateToken, (req, res) => {
    const quoteId = req.params.id;
    const user_id = req.user.id;

    db.query('SELECT * FROM reposts WHERE quote_id = ? AND user_id = ?', [quoteId, user_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results && results.length > 0) {
            db.query('DELETE FROM reposts WHERE quote_id = ? AND user_id = ?', [quoteId, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ reposted: false });
            });
        } else {
            db.query('INSERT INTO reposts (quote_id, user_id) VALUES (?, ?)', [quoteId, user_id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ reposted: true });
            });
        }
    });
});

app.get('/api/quotes/:id', (req, res) => {
    const quoteId = req.params.id;
    const quoteSql = `
        SELECT quotes.id, quotes.content, quotes.created_at, users.id as user_id, users.username, users.profile_pic,
            (SELECT COUNT(*) FROM likes WHERE likes.quote_id = quotes.id) AS likes_count,
            (SELECT COUNT(*) FROM reposts WHERE reposts.quote_id = quotes.id) AS reposts_count
        FROM quotes JOIN users ON quotes.user_id = users.id WHERE quotes.id = ?
    `;
    const commentsSql = `
        SELECT comments.id, comments.content, comments.created_at, comments.user_id, users.username, users.profile_pic 
        FROM comments JOIN users ON comments.user_id = users.id WHERE comments.quote_id = ? ORDER BY comments.created_at ASC
    `;

    db.query(quoteSql, [quoteId], (err, qResults) => {
        if (err || !qResults || qResults.length === 0) return res.status(404).json({ error: 'Quote not found.' });
        db.query(commentsSql, [quoteId], (err, cResults) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ quote: qResults[0], comments: cResults || [] });
        });
    });
});

app.post('/api/quotes/:id/comments', authenticateToken, (req, res) => {
    const quoteId = req.params.id;
    const content = cleanInput(req.body.content);
    const user_id = req.user.id;

    if (!content) return res.status(400).json({ error: 'Comment cannot be empty.' });

    db.query('INSERT INTO comments (quote_id, user_id, content) VALUES (?, ?, ?)', [quoteId, user_id, content], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Comment added.', commentId: result.insertId });
    });
});

// DELETING COMMENT
app.delete('/api/comments/:id', authenticateToken, (req, res) => {
    const commentId = req.params.id;
    const isAuthorized = ['admin', 'moderator', 'editor'].includes(req.user.role);

    let sql = 'DELETE FROM comments WHERE id = ?';
    let params = [commentId];

    if (!isAuthorized) {
        sql += ' AND user_id = ?';
        params.push(req.user.id);
    }

    db.query(sql, params, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Comment permanently deleted.' });
    });
});

// DELETING QUOTE 
app.delete('/api/quotes/:id', authenticateToken, (req, res) => {
    const quoteId = req.params.id;
    const isAuthorized = ['admin', 'moderator', 'editor'].includes(req.user.role);

    let sql = 'DELETE FROM quotes WHERE id = ?';
    let params = [quoteId];

    if (!isAuthorized) {
        sql += ' AND user_id = ?';
        params.push(req.user.id);
    }

    db.query(sql, params, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Quote permanently deleted.' });
    });
});

app.delete('/api/likes/:quoteId', authenticateToken, (req, res) => {
    const quoteId = req.params.quoteId;
    db.query('DELETE FROM likes WHERE quote_id = ? AND user_id = ?', [quoteId, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Like removed.' });
    });
});

app.delete('/api/reposts/:quoteId', authenticateToken, (req, res) => {
    const quoteId = req.params.quoteId;
    db.query('DELETE FROM reposts WHERE quote_id = ? AND user_id = ?', [quoteId, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Repost removed.' });
    });
});

// ADMIN AND ROLE MANAGEMENT

app.get('/api/admin/users', authenticateToken, (req, res) => {
    if (!['admin', 'moderator'].includes(req.user.role)) return res.status(403).json({ error: 'Access denied.' });

    db.query('SELECT id, username, email, role, profile_pic FROM users ORDER BY username ASC', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results || []);
    });
});

app.put('/api/admin/users/:id/role', authenticateToken, (req, res) => {
    if (!['admin', 'moderator'].includes(req.user.role)) return res.status(403).json({ error: 'Access denied.' });

    const userId = req.params.id;
    const { role } = req.body;
    if (!['admin', 'moderator', 'editor', 'user'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });

    db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'User role updated.', role });
    });
});

app.listen(PORT, () => {
    console.log(`Share Your Quotes server running at http://localhost:${PORT}`);
});