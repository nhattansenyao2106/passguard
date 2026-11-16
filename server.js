const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'passguard_vku_super_secret_key_2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE
const db = new sqlite3.Database('./vault.db', (err) => {
    if (err) console.error('Lỗi kết nối DB:', err.message);
    else console.log('Đã kết nối cơ sở dữ liệu SQLite (vault.db).');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        auth_hash TEXT NOT NULL,
        crypto_salt TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vault_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        site_name TEXT NOT NULL,
        username TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// MIDDLEWARE XÁC THỰC TOKEN
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Chưa đăng nhập.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Phiên đăng nhập hết hạn.' });
        req.user = user;
        next();
    });
}

// 1. API ĐĂNG KÝ TÀI KHOẢN
app.post('/api/register', async (req, res) => {
    const { email, authPassword, cryptoSalt } = req.body;
    if (!email || !authPassword || !cryptoSalt) {
        return res.status(400).json({ error: 'Thiếu thông tin bắt buộc.' });
    }

    try {
        const hash = await bcrypt.hash(authPassword, 10);
        db.run(
            `INSERT INTO users (email, auth_hash, crypto_salt) VALUES (?, ?, ?)`,
            [email.toLowerCase(), hash, cryptoSalt],
            function (err) {
                if (err) {
                    return res.status(400).json({ error: 'Email này đã được đăng ký.' });
                }
                res.json({ message: 'Đăng ký thành công! Hãy đăng nhập.' });
            }
        );
    } catch (e) {
        res.status(500).json({ error: 'Lỗi máy chủ.' });
    }
});

// 2. API ĐĂNG NHẬP
app.post('/api/login', (req, res) => {
    const { email, authPassword } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email.toLowerCase()], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Sai email hoặc mật khẩu chính.' });

        const match = await bcrypt.compare(authPassword, user.auth_hash);
        if (!match) return res.status(401).json({ error: 'Sai email hoặc mật khẩu chính.' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
        res.json({
            token,
            email: user.email,
            cryptoSalt: user.crypto_salt
        });
    });
});

// 3. API LẤY DANH SÁCH MẬT KHẨU ĐÃ MÃ HÓA
app.get('/api/vault', authenticateToken, (req, res) => {
    db.all(
        `SELECT id, site_name, username, ciphertext, iv, created_at FROM vault_items WHERE user_id = ? ORDER BY id DESC`,
        [req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Không thể tải dữ liệu két sắt.' });
            res.json(rows);
        }
    );
});

// 4. API LƯU MẬT KHẨU MỚI VÀO KÉT SẮT
app.post('/api/vault', authenticateToken, (req, res) => {
    const { site_name, username, ciphertext, iv } = req.body;
    if (!site_name || !ciphertext || !iv) {
        return res.status(400).json({ error: 'Dữ liệu không hợp lệ.' });
    }

    db.run(
        `INSERT INTO vault_items (user_id, site_name, username, ciphertext, iv) VALUES (?, ?, ?, ?, ?)`,
        [req.user.id, site_name, username || '', ciphertext, iv],
        function (err) {
            if (err) return res.status(500).json({ error: 'Lỗi khi lưu mật khẩu.' });
            res.json({ id: this.lastID, message: 'Đã mã hóa và lưu vào máy chủ.' });
        }
    );
});

// 5. API XÓA MỤC KHỎI KÉT SẮT
app.delete('/api/vault/:id', authenticateToken, (req, res) => {
    db.run(
        `DELETE FROM vault_items WHERE id = ? AND user_id = ?`,
        [req.params.id, req.user.id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Lỗi khi xóa.' });
            res.json({ message: 'Đã xóa thành công.' });
        }
    );
});

app.listen(PORT, () => {
    console.log(`PassGuard Vault đang chạy tại: http://localhost:${PORT}`);
});