const express = require('express');
const axios = require('axios');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session middleware
app.use(session({
  secret: process.env.JWT_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// In-memory user store (replace with DB in production)
let users = [];
let userCookies = {}; // { userId: [cookies] }
let userLogs = {}; // { userId: [logs] }

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to check auth
function authenticateToken(req, res, next) {
  const token = req.session.token;
  if (!token) return res.redirect('/login');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.redirect('/login');
    req.user = user;
    next();
  });
}

const ua_list = [
  "Mozilla/5.0 (Linux; Android 10; Wildfire E Lite) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/105.0.5195.136 Mobile Safari/537.36[FBAN/EMA;FBLC/en_US;FBAV/298.0.0.10.115;]",
  "Mozilla/5.0 (Linux; Android 11; KINGKONG 5 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/320.0.0.12.108;]",
  "Mozilla/5.0 (Linux; Android 11; G91 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/106.0.5249.126 Mobile Safari/537.36[FBAN/EMA;FBLC/fr_FR;FBAV/325.0.1.4.108;]"
];

function extract_token(cookie, ua) {
  return axios.get("https://business.facebook.com/business_locations", {
    headers: {
      "user-agent": ua,
      "referer": "https://www.facebook.com/",
      "Cookie": cookie
    }
  }).then(res => {
    const tokenMatch = res.data.match(/(EAAG\w+)/);
    return tokenMatch ? tokenMatch[1] : null;
  }).catch(err => {
    console.error('Token extraction error:', err.message);
    return null;
  });
}

// Routes
app.get("/", (req, res) => {
  res.render("index", { title: "Facebook Share Booster - Intro" });
});

app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up" });
});

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send("Missing fields");
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, email, password: hashedPassword });
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send("Invalid credentials");
  }
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
  req.session.token = token;
  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/dashboard", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const cookies = userCookies[userId] || [];
  res.render("dashboard", { title: "Dashboard", cookies });
});

app.post("/dashboard/add-cookie", authenticateToken, (req, res) => {
  const { cookie } = req.body;
  const userId = req.user.id;
  if (!userCookies[userId]) userCookies[userId] = [];
  userCookies[userId].push(cookie);
  res.redirect("/dashboard");
});

app.post("/dashboard/bulk-add", authenticateToken, (req, res) => {
  const { cookies } = req.body;
  const userId = req.user.id;
  if (!userCookies[userId]) userCookies[userId] = [];
  const cookieList = cookies.split('\n').map(c => c.trim()).filter(c => c);
  userCookies[userId].push(...cookieList);
  res.redirect("/dashboard");
});

app.get("/share", authenticateToken, (req, res) => {
  res.render("share", { title: "Share Tool" });
});

app.post("/api/share", authenticateToken, async (req, res) => {
  const { link: post_link, limit } = req.body;
  const limitNum = parseInt(limit, 10);
  const userId = req.user.id;
  const cookies = userCookies[userId] || [];
  if (!cookies.length || !post_link || !limitNum) {
    return res.json({ status: false, message: "Missing input or no cookies." });
  }

  let success = 0;
  for (let i = 0; i < Math.min(limitNum, cookies.length); i++) {
    const cookie = cookies[i];
    const ua = ua_list[Math.floor(Math.random() * ua_list.length)];
    const token = await extract_token(cookie, ua);
    if (!token) continue;

    try {
      const response = await axios.post(
        "https://graph.facebook.com/v18.0/me/feed",
        null,
        {
          params: { link: post_link, access_token: token, published: 0 },
          headers: { "user-agent": ua, "Cookie": cookie }
        }
      );
      if (response.data.id) {
        success++;
        io.emit('share-update', { userId, message: `Shared ${success} times.` });
      }
    } catch (err) {
      console.error('Share error:', err.message);
    }
  }

  if (!userLogs[userId]) userLogs[userId] = [];
  userLogs[userId].push({ time: new Date(), link: post_link, success });
  res.json({ status: true, message: `✅ Shared ${success} times.`, success_count: success });
});

app.get("/logs", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const logs = userLogs[userId] || [];
  res.render("logs", { title: "Logs", logs });
});

// Socket.IO for real-time
io.on('connection', (socket) => {
  console.log('User connected');
});

const port = process.env.PORT || 5000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});