import express from 'express';
import session from 'express-session';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_STATIC = path.resolve(__dirname, '..'); // 정적 사이트 루트
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// 한국 시간대(KST) 날짜 생성 함수
function getKSTDateTime() {
  const now = new Date();
  // UTC 시간에 9시간을 더해서 KST로 변환
  const kstOffset = 9 * 60 * 60 * 1000; // 9시간을 밀리초로 변환
  const kstTime = new Date(now.getTime() + kstOffset);
  // UTC 메서드를 사용하여 KST 시간을 추출 (이미 9시간을 더했으므로 UTC 메서드 사용)
  const year = kstTime.getUTCFullYear();
  const month = String(kstTime.getUTCMonth() + 1).padStart(2, '0');
  const day = String(kstTime.getUTCDate()).padStart(2, '0');
  const hours = String(kstTime.getUTCHours()).padStart(2, '0');
  const minutes = String(kstTime.getUTCMinutes()).padStart(2, '0');
  const seconds = String(kstTime.getUTCSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

// Multer 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB 제한
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype) || file.mimetype === 'application/pdf';
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('이미지 파일 또는 PDF 파일만 업로드 가능합니다.'));
  }
});

const app = express();

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Health Check Endpoint (Render.com에서 필요) - CORS 미들웨어 전에 배치
app.get("/healthz", (req, res) => res.sendStatus(200));

// CORS 설정 (세션 설정 전에 추가)
const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.RENDER_EXTERNAL_URL, // Render 백엔드 자체 URL
  'http://localhost:3000',
  'http://localhost:5000',
  'http://localhost:8080'
].filter(Boolean); // undefined 값 제거

// 환경 변수에서 추가 origin 허용 (쉼표로 구분)
if (process.env.ALLOWED_ORIGINS) {
  allowedOrigins.push(...process.env.ALLOWED_ORIGINS.split(',').map(url => url.trim()));
}

app.use(cors({
  origin: function (origin, callback) {
    // origin이 없는 경우 (같은 도메인 요청, Postman 등) 허용
    if (!origin) return callback(null, true);
    
    // 개발 환경에서는 모든 origin 허용
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // 프로덕션 환경에서는 허용된 origin만 허용
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      // 백엔드 자체 도메인인 경우 허용 (Render Health Check 등)
      const backendUrl = process.env.RENDER_EXTERNAL_URL;
      if (backendUrl && origin.startsWith(backendUrl)) {
        return callback(null, true);
      }
      // Render 백엔드 도메인 패턴 허용 (.onrender.com)
      if (origin.includes('.onrender.com')) {
        return callback(null, true);
      }
      console.warn(`CORS: Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(ROOT_STATIC)); // 기존 정적 파일 그대로 서빙

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'replace-this-secret-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      secure: process.env.NODE_ENV === 'production' // HTTPS에서만 쿠키 전송
    }
  })
);

// DB
let db;
async function initDb() {
  db = await open({ filename: path.join(__dirname, 'app.db'), driver: sqlite3.Database });
  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      birthdate TEXT,
      gender TEXT CHECK(gender IN ('M','F')),
      email TEXT,
      phone TEXT,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS coop_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      birthdate TEXT,
      gender TEXT CHECK(gender IN ('M','F')),
      email TEXT,
      phone TEXT,
      address TEXT,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS golf_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      birthdate TEXT,
      gender TEXT CHECK(gender IN ('M','F')),
      email TEXT,
      phone TEXT,
      address TEXT,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_path TEXT,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS post_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      image_path TEXT NOT NULL,
      display_order INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS sponsors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT,
      sponsor_type TEXT NOT NULL,
      amount INTEGER,
      payment_method TEXT,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS site_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT NOT NULL,
      display_order INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS notices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      icon_class TEXT,
      icon_color TEXT,
      notice_date TEXT,
      link TEXT,
      display_order INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS coop_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_path TEXT,
      is_notice INTEGER NOT NULL DEFAULT 0,
      view_count INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES coop_users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS coop_post_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      image_path TEXT NOT NULL,
      display_order INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(post_id) REFERENCES coop_posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS golf_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_path TEXT,
      is_notice INTEGER NOT NULL DEFAULT 0,
      view_count INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES golf_users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS golf_post_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      image_path TEXT NOT NULL,
      display_order INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(post_id) REFERENCES golf_posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS coop_accessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      birthdate TEXT NOT NULL,
      phone TEXT NOT NULL,
      address TEXT NOT NULL,
      email TEXT NOT NULL,
      disability_type TEXT NOT NULL,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS coop_accession_documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      accession_id INTEGER NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER,
      display_order INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(accession_id) REFERENCES coop_accessions(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS coop_solar_gallery (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      image_path TEXT NOT NULL,
      title TEXT NOT NULL,
      status_badge TEXT,
      date_text TEXT,
      display_order INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS golf_gallery (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      image_path TEXT NOT NULL,
      title TEXT NOT NULL,
      status_badge TEXT,
      date_text TEXT,
      display_order INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME
    );
  `);
  
  // 마이그레이션: 기존 테이블에 컬럼 추가
  try {
    const tableInfo = await db.all("PRAGMA table_info(posts)");
    const columns = tableInfo.map(col => col.name);
    
    if (!columns.includes('category')) {
      await db.run('ALTER TABLE posts ADD COLUMN category TEXT NOT NULL DEFAULT "general"');
      console.log('[마이그레이션] category 컬럼 추가됨');
    }
    
    if (!columns.includes('image_path')) {
      await db.run('ALTER TABLE posts ADD COLUMN image_path TEXT');
      console.log('[마이그레이션] image_path 컬럼 추가됨');
    }
    
    if (!columns.includes('is_notice')) {
      await db.run('ALTER TABLE posts ADD COLUMN is_notice INTEGER NOT NULL DEFAULT 0');
      console.log('[마이그레이션] is_notice 컬럼 추가됨');
    }
    
    if (!columns.includes('view_count')) {
      await db.run('ALTER TABLE posts ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0');
      console.log('[마이그레이션] view_count 컬럼 추가됨');
    }
    
    // users 테이블 마이그레이션
    const usersTableInfo = await db.all("PRAGMA table_info(users)");
    const usersColumns = usersTableInfo.map(col => col.name);
    
    if (!usersColumns.includes('is_active')) {
      await db.run('ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1');
      console.log('[마이그레이션] users.is_active 컬럼 추가됨');
    }
    
    if (!usersColumns.includes('name')) {
      await db.run('ALTER TABLE users ADD COLUMN name TEXT');
      console.log('[마이그레이션] users.name 컬럼 추가됨');
    }
    
    // post_images 테이블 생성 확인
    const imagesTableExists = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='post_images'");
    if (!imagesTableExists) {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS post_images (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          post_id INTEGER NOT NULL,
          image_path TEXT NOT NULL,
          display_order INTEGER NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
        )
      `);
      console.log('[마이그레이션] post_images 테이블 생성됨');
    }
  } catch (error) {
    console.error('[마이그레이션 오류]', error.message);
  }
  
  // seed admin accounts (5개) - 관악구장애인단체연합회
  const adminAccounts = [
    { username: 'admin', password: 'admin12341234', email: 'admin@example.com', name: '관리자1' },
    { username: 'admin2', password: 'admin1234', email: 'admin2@example.com', name: '관리자2' },
    { username: 'admin3', password: 'admin1234', email: 'admin3@example.com', name: '관리자3' },
    { username: 'admin4', password: 'admin1234', email: 'admin4@example.com', name: '관리자4' },
    { username: 'admin5', password: 'admin1234', email: 'admin5@example.com', name: '관리자5' }
  ];
  
  console.log('\n[관리자 계정 생성 - 관악구장애인단체연합회]');
  for (const account of adminAccounts) {
    const existing = await db.get('SELECT * FROM users WHERE username = ? LIMIT 1', [account.username]);
    if (!existing) {
      const hash = await bcrypt.hash(account.password, 10);
      await db.run(
        'INSERT INTO users (username, password_hash, is_admin, email, name) VALUES (?, ?, 1, ?, ?)',
        [account.username, hash, account.email, account.name]
      );
      console.log(`아이디: ${account.username} | 비밀번호: ${account.password} | 이름: ${account.name}`);
    }
  }
  
  // seed coop admin accounts - 전국장애인나눔협동조합
  const coopAdminAccounts = [
    { username: 'coop_admin', password: 'coop1234', email: 'coop@example.com', name: '협동조합관리자1' },
    { username: 'coop_admin2', password: 'coop1234', email: 'coop2@example.com', name: '협동조합관리자2' }
  ];
  
  console.log('\n[관리자 계정 생성 - 전국장애인나눔협동조합]');
  for (const account of coopAdminAccounts) {
    const existing = await db.get('SELECT * FROM coop_users WHERE username = ? LIMIT 1', [account.username]);
    if (!existing) {
      const hash = await bcrypt.hash(account.password, 10);
      await db.run(
        'INSERT INTO coop_users (username, password_hash, is_admin, email, name) VALUES (?, ?, 1, ?, ?)',
        [account.username, hash, account.email, account.name]
      );
      console.log(`아이디: ${account.username} | 비밀번호: ${account.password} | 이름: ${account.name}`);
    }
  }
  
  // seed golf admin accounts - 한국장애인스크린파크골프협회
  const golfAdminAccounts = [
    { username: 'golf_admin', password: 'golf1234', email: 'golf@example.com', name: '골프협회관리자1' },
    { username: 'golf_admin2', password: 'golf1234', email: 'golf2@example.com', name: '골프협회관리자2' }
  ];
  
  console.log('\n[관리자 계정 생성 - 한국장애인스크린파크골프협회]');
  for (const account of golfAdminAccounts) {
    const existing = await db.get('SELECT * FROM golf_users WHERE username = ? LIMIT 1', [account.username]);
    if (!existing) {
      const hash = await bcrypt.hash(account.password, 10);
      await db.run(
        'INSERT INTO golf_users (username, password_hash, is_admin, email, name) VALUES (?, ?, 1, ?, ?)',
        [account.username, hash, account.email, account.name]
      );
      console.log(`아이디: ${account.username} | 비밀번호: ${account.password} | 이름: ${account.name}`);
    }
  }
  console.log('(첫 로그인 후 비밀번호 변경 권장)\n');
  
  // 관리자 계정 비밀번호 강제 재설정 (긴급 복구용)
  console.log('\n[관리자 계정 비밀번호 강제 재설정]');
  const resetAccounts = [
    { table: 'coop_users', username: 'coopadmin', password: 'admin1234' },
    { table: 'coop_users', username: 'coop_admin', password: 'coop1234' },
    { table: 'coop_users', username: 'coop_admin2', password: 'coop1234' }
  ];
  
  for (const account of resetAccounts) {
    const user = await db.get(`SELECT id FROM ${account.table} WHERE username = ?`, [account.username]);
    if (user) {
      const hash = await bcrypt.hash(account.password, 10);
      await db.run(`UPDATE ${account.table} SET password_hash = ? WHERE username = ?`, [hash, account.username]);
      console.log(`[재설정] ${account.table}: ${account.username} | 비밀번호: ${account.password}`);
    }
  }
  console.log('');
}

// Helpers
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    // 원래 가려던 URL을 저장하고 로그인 페이지로 리다이렉트
    const returnTo = req.originalUrl || req.url;
    return res.redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
  }
  next();
}
function requirePostOwnerOrAdmin() {
  return async (req, res, next) => {
    const { id } = req.params;
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [id]);
    if (!post) return res.status(404).send('Not Found');
    if (req.session.user?.is_admin || req.session.user?.id === post.user_id) return next();
    return res.status(403).send('Forbidden');
  };
}

function requireAdmin(req, res, next) {
  if (!req.session.user?.is_admin) return res.status(403).send('관리자만 접근 가능합니다.');
  next();
}

// 카테고리별 게시판 라우트
const categories = {
  'info': { name: '정보마당', route: '/info.html' },
  'lovehouse': { name: '러브하우스', route: '/activity-lovehouse.html' },
  'volunteer': { name: '행사 및 환경봉사단', route: '/activity-volunteer.html' },
  'mobilitycare': { name: '전동보장구교육&케어', route: '/activity-mobilitycare.html' },
  'beauty': { name: '무료 이·미용 봉사', route: '/activity-beauty.html' }
};

// 카테고리별 게시판 목록
app.get('/category/:category', async (req, res) => {
  const { category } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = 15; // 가로 3개 x 세로 5줄 = 15개
  const offset = (page - 1) * limit;
  
  if (!categories[category]) return res.status(404).send('Not Found');
  
  // 전체 게시글 수 조회
  const totalCount = await db.get(
    'SELECT COUNT(*) as count FROM posts WHERE category = ?',
    [category]
  );
  const totalPosts = totalCount.count;
  const totalPages = Math.ceil(totalPosts / limit);
  
  const posts = await db.all(
    `SELECT p.id, p.title, p.content, p.image_path, p.created_at, p.updated_at, 
            CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
            u.id as user_id
     FROM posts p JOIN users u ON u.id = p.user_id
     WHERE p.category = ?
     ORDER BY p.created_at DESC
     LIMIT ? OFFSET ?`,
    [category, limit, offset]
  );
  
  // 각 게시글의 첫 번째 이미지 가져오기
  for (const post of posts) {
    const firstImage = await db.get(
      'SELECT image_path FROM post_images WHERE post_id = ? ORDER BY display_order ASC LIMIT 1',
      [post.id]
    );
    if (firstImage) {
      post.first_image = firstImage.image_path;
    } else if (post.image_path) {
      post.first_image = post.image_path;
    }
  }
  
  res.json({ 
    posts, 
    categoryName: categories[category].name,
    pagination: {
      currentPage: page,
      totalPages: totalPages,
      totalPosts: totalPosts,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  });
});

// 카테고리별 게시판 새 글 작성 (관리자만)
app.get('/category/:category/new', requireLogin, requireAdmin, (req, res) => {
  const { category } = req.params;
  if (!categories[category]) return res.status(404).send('Not Found');
  res.render('board/new', { error: null, category, categoryName: categories[category].name });
});

// 카테고리별 게시판 글 작성 (관리자만)
app.post('/category/:category', requireLogin, requireAdmin, upload.array('images', 15), async (req, res) => {
  const { category } = req.params;
  if (!categories[category]) return res.status(404).send('Not Found');
  
  const { title, content, businessName, date, target, participants, phone, hours } = req.body;
  if (!title?.trim() || !content?.trim()) {
    return res.render('board/new', { 
      error: '제목과 내용을 입력하세요.', 
      category, 
      categoryName: categories[category].name 
    });
  }
  
  // 사업 정보가 있는 카테고리인 경우 content에 추가
  const projectCategories = ['lovehouse', 'volunteer', 'mobilitycare', 'beauty'];
  let finalContent = content.trim();
  
  if (projectCategories.includes(category)) {
    const projectInfo = [];
    if (businessName?.trim()) projectInfo.push(`사업명: ${businessName.trim()}`);
    if (date?.trim()) projectInfo.push(`실시일: ${date.trim()}`);
    if (target?.trim()) projectInfo.push(`대상: ${target.trim()}`);
    if (participants?.trim()) projectInfo.push(`참여인원: ${participants.trim()}`);
    if (phone?.trim()) projectInfo.push(`전화: ${phone.trim()}`);
    if (hours?.trim()) projectInfo.push(`접수시간: ${hours.trim()}`);
    
    if (projectInfo.length > 0) {
      finalContent = projectInfo.join('\n') + '\n\n' + finalContent;
    }
  }
  
  // 게시글 생성 (한국 시간대 명시)
  const kstDateTime = getKSTDateTime();
  const result = await db.run(
    'INSERT INTO posts (user_id, category, title, content, image_path, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [req.session.user.id, category, title.trim(), finalContent, null, kstDateTime]
  );
  const postId = result.lastID;
  
  // 여러 이미지 저장
  if (req.files && req.files.length > 0) {
    const firstImage = `/public/uploads/${req.files[0].filename}`;
    // 첫 번째 이미지를 posts 테이블의 image_path에 저장 (목록 표시용)
    await db.run('UPDATE posts SET image_path = ? WHERE id = ?', [firstImage, postId]);
    
    // 모든 이미지를 post_images 테이블에 저장
    for (let i = 0; i < req.files.length; i++) {
      const imagePath = `/public/uploads/${req.files[i].filename}`;
      await db.run(
        'INSERT INTO post_images (post_id, image_path, display_order) VALUES (?, ?, ?)',
        [postId, imagePath, i]
      );
    }
  }
  
  res.redirect(categories[category].route);
});

// 카테고리별 게시판 글 수정 (관리자만)
app.get('/category/:category/posts/:id/edit', requireLogin, requireAdmin, async (req, res) => {
  const { category, id } = req.params;
  const post = await db.get('SELECT * FROM posts WHERE id = ? AND category = ?', [id, category]);
  if (!post) return res.status(404).send('Not Found');
  
  const images = await db.all(
    'SELECT id, image_path, display_order FROM post_images WHERE post_id = ? ORDER BY display_order ASC',
    [id]
  );
  
  res.render('board/edit', { post, images, error: null, category, categoryName: categories[category].name });
});

app.post('/category/:category/posts/:id', requireLogin, requireAdmin, upload.array('images', 15), async (req, res) => {
  const { category, id } = req.params;
  const { title, content, deleteImages, businessName, date, target, participants, phone, hours } = req.body;
  
  if (!title?.trim() || !content?.trim()) {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [id]);
    return res.render('board/edit', { 
      post, 
      error: '제목과 내용을 입력하세요.', 
      category, 
      categoryName: categories[category].name 
    });
  }
  
  // 사업 정보가 있는 카테고리인 경우 content에 추가
  const projectCategories = ['lovehouse', 'volunteer', 'mobilitycare', 'beauty'];
  let finalContent = content.trim();
  
  if (projectCategories.includes(category)) {
    const projectInfo = [];
    if (businessName?.trim()) projectInfo.push(`사업명: ${businessName.trim()}`);
    if (date?.trim()) projectInfo.push(`실시일: ${date.trim()}`);
    if (target?.trim()) projectInfo.push(`대상: ${target.trim()}`);
    if (participants?.trim()) projectInfo.push(`참여인원: ${participants.trim()}`);
    
    if (projectInfo.length > 0) {
      finalContent = projectInfo.join('\n') + '\n\n' + finalContent;
    }
  }
  
  // 삭제할 이미지 처리
  if (deleteImages) {
    const deleteIds = Array.isArray(deleteImages) ? deleteImages : [deleteImages];
    for (const imgId of deleteIds) {
      const img = await db.get('SELECT image_path FROM post_images WHERE id = ?', [imgId]);
      if (img) {
        const imgPath = path.join(__dirname, img.image_path);
        if (fs.existsSync(imgPath)) {
          fs.unlinkSync(imgPath);
        }
        await db.run('DELETE FROM post_images WHERE id = ?', [imgId]);
      }
    }
  }
  
  // 새 이미지 추가
  if (req.files && req.files.length > 0) {
    const existingImages = await db.all('SELECT display_order FROM post_images WHERE post_id = ? ORDER BY display_order DESC LIMIT 1', [id]);
    let nextOrder = existingImages.length > 0 ? existingImages[0].display_order + 1 : 0;
    
    for (let i = 0; i < req.files.length; i++) {
      const imagePath = `/public/uploads/${req.files[i].filename}`;
      await db.run(
        'INSERT INTO post_images (post_id, image_path, display_order) VALUES (?, ?, ?)',
        [id, imagePath, nextOrder + i]
      );
    }
    
    // 첫 번째 이미지를 posts 테이블의 image_path에 업데이트
    const firstImage = await db.get('SELECT image_path FROM post_images WHERE post_id = ? ORDER BY display_order ASC LIMIT 1', [id]);
    if (firstImage) {
      await db.run('UPDATE posts SET image_path = ? WHERE id = ?', [firstImage.image_path, id]);
    }
  }
  
  await db.run(
    'UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [title.trim(), content.trim(), id]
  );
  
  res.redirect(categories[category].route);
});

// 게시글 상세 조회
app.get('/category/:category/posts/:id', async (req, res) => {
  const { category, id } = req.params;
  if (!categories[category]) return res.status(404).send('Not Found');
  
  const post = await db.get(
    `SELECT p.id, p.title, p.content, p.image_path, p.created_at, p.updated_at, p.category,
            CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
            u.id as user_id
     FROM posts p JOIN users u ON u.id = p.user_id
     WHERE p.id = ? AND p.category = ?`,
    [id, category]
  );
  
  if (!post) return res.status(404).send('Not Found');
  
  // 조회수 증가
  await db.run('UPDATE posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?', [id]);
  
  let images = await db.all(
    'SELECT id, image_path, display_order FROM post_images WHERE post_id = ? ORDER BY display_order ASC',
    [id]
  );
  
  // 이미지가 없고 posts 테이블에 image_path가 있으면 그것도 추가 (기존 데이터 호환성)
  if (images.length === 0 && post.image_path) {
    images = [{ id: null, image_path: post.image_path, display_order: 0 }];
  }
  
  res.render('board/detail', { 
    post, 
    images: images || [], 
    category: post.category,
    categoryName: categories[category].name,
    categoryRoute: categories[category].route
  });
});

// 카테고리별 게시판 글 삭제 (관리자만)
app.post('/category/:category/posts/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  const { category, id } = req.params;
  
  // post_images 테이블의 모든 이미지 삭제
  const images = await db.all('SELECT image_path FROM post_images WHERE post_id = ?', [id]);
  for (const img of images) {
    const imgPath = path.join(__dirname, img.image_path);
    if (fs.existsSync(imgPath)) {
      fs.unlinkSync(imgPath);
    }
  }
  
  // posts 테이블의 이미지 삭제
  const post = await db.get('SELECT image_path FROM posts WHERE id = ?', [id]);
  if (post?.image_path) {
    const imagePath = path.join(__dirname, post.image_path);
    if (fs.existsSync(imagePath)) {
      fs.unlinkSync(imagePath);
    }
  }
  
  await db.run('DELETE FROM posts WHERE id = ?', [id]);
  res.redirect(categories[category].route);
});

// Routes
// 게시판 페이지 리다이렉트
app.get('/board', (req, res) => {
  res.redirect('/board.html');
});

// 게시판 API (공지사항과 일반 게시글 분리)
app.get('/api/board', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const notices = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM posts p JOIN users u ON u.id = p.user_id
       WHERE p.category = 'general' AND p.is_notice = 1
       ORDER BY p.created_at DESC`
    );
    
    // 전체 게시글 수 조회
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM posts 
       WHERE category = 'general' AND (is_notice = 0 OR is_notice IS NULL)`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM posts p JOIN users u ON u.id = p.user_id
       WHERE p.category = 'general' AND (p.is_notice = 0 OR p.is_notice IS NULL)
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      notices: notices || [], 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/board:', error);
    res.status(500).json({ error: '게시글을 불러오는 중 오류가 발생했습니다.' });
  }
});

// 자유게시판 API
app.get('/api/board/free', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    // 전체 게시글 수 조회
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM posts 
       WHERE category = 'free'`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM posts p JOIN users u ON u.id = p.user_id
       WHERE p.category = 'free'
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/board/free:', error);
    res.status(500).json({ 
      error: '게시글을 불러오는 중 오류가 발생했습니다.',
      notices: [],
      posts: [],
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalPosts: 0,
        limit: 20,
        hasNext: false,
        hasPrev: false
      }
    });
  }
});

app.get('/board/new', requireLogin, (req, res) => {
  const category = req.query.category || null;
  let categoryName = '게시판';
  
  if (category === 'free') {
    categoryName = '자유게시판';
  } else if (category === 'general') {
    // 일반게시판은 관리자만 글쓰기 가능
    if (!req.session.user.is_admin) {
      return res.status(403).send('일반게시판은 관리자만 글을 작성할 수 있습니다.');
    }
    categoryName = '일반게시판';
  }
  
  res.render('board/new', { 
    error: null, 
    category: category,
    categoryName: categoryName,
    currentUser: req.session.user 
  });
});

// 게시글 상세 조회 (일반게시판, 자유게시판 모두)
app.get('/posts/:id', async (req, res) => {
  const post = await db.get(
    `SELECT p.id, p.title, p.content, p.image_path, p.created_at, p.updated_at, p.is_notice, p.view_count, p.category,
            CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
            u.id as user_id
     FROM posts p JOIN users u ON u.id = p.user_id
     WHERE p.id = ? AND (p.category = 'general' OR p.category = 'free')`,
    [req.params.id]
  );
  
  if (!post) return res.status(404).send('Not Found');
  
  // 조회수 증가
  await db.run('UPDATE posts SET view_count = view_count + 1 WHERE id = ?', [req.params.id]);
  post.view_count = (post.view_count || 0) + 1;
  
  // 이미지 가져오기
  let images = await db.all(
    'SELECT id, image_path, display_order FROM post_images WHERE post_id = ? ORDER BY display_order ASC',
    [req.params.id]
  );
  
  // 이미지가 없고 posts 테이블에 image_path가 있으면 그것도 추가 (기존 데이터 호환성)
  if (images.length === 0 && post.image_path) {
    images = [{ id: null, image_path: post.image_path, display_order: 0 }];
  }
  
  const categoryName = post.category === 'free' ? '자유게시판' : '게시판';
  
  res.render('board/detail', { 
    post, 
    images: images || [], 
    category: post.category,
    categoryName: categoryName,
    categoryRoute: '/board.html'
  });
});

app.post('/posts', requireLogin, upload.array('images', 15), async (req, res) => {
  const { title, content, is_notice, category, businessName, date, target, participants, phone, hours } = req.body;
  const postCategory = category || 'general';
  
  // 디버깅: 체크박스 값 확인
  console.log('[POST /posts] is_notice 값:', is_notice, '타입:', typeof is_notice);
  
  if (!title?.trim() || !content?.trim()) {
    return res.render('board/new', { 
      error: '제목과 내용을 입력하세요.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : (categories[postCategory] ? categories[postCategory].name : '일반게시판'),
      currentUser: req.session.user 
    });
  }
  
  // 일반게시판은 관리자만 작성 가능
  if (postCategory === 'general' && !req.session.user.is_admin) {
    return res.render('board/new', { 
      error: '일반게시판은 관리자만 글을 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: '일반게시판',
      currentUser: req.session.user 
    });
  }
  
  // 공지사항은 관리자만 작성 가능
  // 체크박스가 체크되면 '1' 또는 'on'이 전송됨, 체크되지 않으면 undefined
  const isNotice = (is_notice === 'on' || is_notice === '1' || is_notice === 1) ? 1 : 0;
  console.log('[POST /posts] 최종 isNotice 값:', isNotice);
  if (isNotice && !req.session.user.is_admin) {
    return res.render('board/new', { 
      error: '공지사항은 관리자만 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : (categories[postCategory] ? categories[postCategory].name : '일반게시판'),
      currentUser: req.session.user 
    });
  }
  
  // 사업 정보가 있는 카테고리인 경우 content에 추가
  const projectCategories = ['lovehouse', 'volunteer', 'mobilitycare', 'beauty'];
  let finalContent = content.trim();
  
  if (projectCategories.includes(postCategory)) {
    const projectInfo = [];
    if (businessName?.trim()) projectInfo.push(`사업명: ${businessName.trim()}`);
    if (date?.trim()) projectInfo.push(`실시일: ${date.trim()}`);
    if (target?.trim()) projectInfo.push(`대상: ${target.trim()}`);
    if (participants?.trim()) projectInfo.push(`참여인원: ${participants.trim()}`);
    if (phone?.trim()) projectInfo.push(`전화: ${phone.trim()}`);
    if (hours?.trim()) projectInfo.push(`접수시간: ${hours.trim()}`);
    
    if (projectInfo.length > 0) {
      finalContent = projectInfo.join('\n') + '\n\n' + finalContent;
    }
  }
  
  // 게시글 생성 (한국 시간대 명시)
  const kstDateTime = getKSTDateTime();
  console.log('[POST /posts] DB 저장 전 - isNotice:', isNotice, 'postCategory:', postCategory);
  const result = await db.run('INSERT INTO posts (user_id, category, title, content, is_notice, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
    req.session.user.id,
    postCategory,
    title.trim(),
    finalContent,
    isNotice,
    kstDateTime
  ]);
  const postId = result.lastID;
  
  // 저장 후 확인
  const savedPost = await db.get('SELECT id, category, is_notice FROM posts WHERE id = ?', [postId]);
  console.log('[POST /posts] DB 저장 후 확인 - postId:', savedPost.id, 'category:', savedPost.category, 'is_notice:', savedPost.is_notice);
  
  // 이미지 저장
  if (req.files && req.files.length > 0) {
    const firstImage = `/public/uploads/${req.files[0].filename}`;
    // 첫 번째 이미지를 posts 테이블의 image_path에 저장 (목록 표시용)
    await db.run('UPDATE posts SET image_path = ? WHERE id = ?', [firstImage, postId]);
    
    // 모든 이미지를 post_images 테이블에 저장
    for (let i = 0; i < req.files.length; i++) {
      const imagePath = `/public/uploads/${req.files[i].filename}`;
      await db.run(
        'INSERT INTO post_images (post_id, image_path, display_order) VALUES (?, ?, ?)',
        [postId, imagePath, i]
      );
    }
  }
  
  // 카테고리가 있으면 해당 카테고리 페이지로, 없으면 게시판으로 리다이렉트
  if (postCategory && categories[postCategory]) {
    res.redirect(categories[postCategory].route);
  } else {
    res.redirect('/board.html');
  }
});

app.get('/posts/:id/edit', requireLogin, requirePostOwnerOrAdmin(), async (req, res) => {
  const post = await db.get('SELECT * FROM posts WHERE id = ?', [req.params.id]);
  if (!post) return res.status(404).send('Not Found');
  res.render('board/edit', { post, error: null, category: null, categoryName: null });
});

app.post('/posts/:id', requireLogin, requirePostOwnerOrAdmin(), async (req, res) => {
  const { title, content } = req.body;
  if (!title?.trim() || !content?.trim()) {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    return res.render('board/edit', { post, error: '제목과 내용을 입력하세요.', category: null, categoryName: null });
  }
  await db.run('UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [
    title.trim(),
    content.trim(),
    req.params.id
  ]);
  res.redirect('/board.html');
});

app.post('/posts/:id/delete', requireLogin, requirePostOwnerOrAdmin(), async (req, res) => {
  await db.run('DELETE FROM posts WHERE id = ?', [req.params.id]);
  res.redirect('/board.html');
});

// Auth
app.get('/register', (req, res) => res.render('auth/register', { error: null }));
app.post('/register', async (req, res) => {
  const { username, password, name, birthdate, gender, email, phone, address } = req.body;
  if (!username || !password) {
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    return res.render('auth/register', { error: '아이디와 비밀번호를 입력하세요.' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run(
      'INSERT INTO users (username, password_hash, name, birthdate, gender, email, phone) VALUES (?,?,?,?,?,?,?)',
      [username.trim(), hash, name || null, birthdate || null, gender || null, email || null, phone || null]
    );
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: true, message: '회원가입이 완료되었습니다.' });
    }
    res.redirect('/login');
  } catch (e) {
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(400).json({ error: '이미 존재하는 아이디이거나 오류가 발생했습니다.' });
    }
    res.render('auth/register', { error: '이미 존재하는 아이디이거나 오류가 발생했습니다.' });
  }
});

app.get('/login', (req, res) => {
  const returnTo = req.query.returnTo || '/index.html';
  res.render('auth/login', { error: null, returnTo });
});
app.post('/login', async (req, res) => {
  const { username, password, returnTo } = req.body;
  
  // 데이터베이스 연결 확인
  if (!db) {
    console.error('[LOGIN ERROR] Database not initialized');
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(503).json({ error: '서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.' });
    }
    return res.render('auth/login', { error: '서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.', returnTo: returnTo || '/index.html' });
  }
  
  if (!username || !password) {
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    return res.render('auth/login', { error: '아이디와 비밀번호를 입력하세요.', returnTo: returnTo || '/index.html' });
  }
  
  try {
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.render('auth/login', { error: '아이디 또는 비밀번호가 올바르지 않습니다.', returnTo: returnTo || '/index.html' });
    }
    
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.render('auth/login', { error: '아이디 또는 비밀번호가 올바르지 않습니다.', returnTo: returnTo || '/index.html' });
    }
    
    req.session.user = { id: user.id, username: user.username, is_admin: !!user.is_admin };
    
    // JSON 요청인 경우 JSON 응답
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ 
        success: true, 
        message: '로그인 성공',
        user: {
          id: user.id,
          username: user.username,
          isAdmin: !!user.is_admin
        }
      });
    }
    
    // HTML 폼 요청인 경우 리다이렉트
    res.redirect(returnTo || '/index.html');
  } catch (error) {
    console.error('[LOGIN ERROR]', error);
    console.error('[LOGIN ERROR] Stack:', error.stack);
    console.error('[LOGIN ERROR] Username:', username);
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(500).json({ error: '로그인 중 오류가 발생했습니다.', details: process.env.NODE_ENV === 'production' ? undefined : error.message });
    }
    return res.render('auth/login', { error: '로그인 중 오류가 발생했습니다.', returnTo: returnTo || '/index.html' });
  }
});
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(500).json({ error: '로그아웃 중 오류가 발생했습니다.' });
      }
      return res.redirect('/');
    }
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: true, message: '로그아웃되었습니다.' });
    }
    res.redirect('/');
  });
});

// 사용자 세션 정보 API
app.get('/api/user', (req, res) => {
  if (req.session.user) {
    res.json({ 
      loggedIn: true, 
      username: req.session.user.username,
      isAdmin: !!req.session.user.is_admin 
    });
  } else {
    res.json({ loggedIn: false, username: null, isAdmin: false });
  }
});

// ========== 전국장애인나눔협동조합 (Coop) 라우트 ==========
// Coop 로그인
app.get('/coop/login', (req, res) => {
  const returnTo = req.query.returnTo || '/nanum.html';
  res.redirect(`/coop-login.html?returnTo=${encodeURIComponent(returnTo)}`);
});
app.post('/coop/login', async (req, res) => {
  const { username, password, returnTo } = req.body;
  
  // 데이터베이스 연결 확인
  if (!db) {
    console.error('[COOP LOGIN ERROR] Database not initialized');
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(503).json({ error: '서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.' });
    }
    return res.redirect(`/coop-login.html?error=서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
  }
  
  if (!username || !password) {
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    return res.redirect(`/coop-login.html?error=아이디와 비밀번호를 입력하세요.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
  }
  
  try {
    const user = await db.get('SELECT * FROM coop_users WHERE username = ?', [username]);
    if (!user) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.redirect(`/coop-login.html?error=아이디 또는 비밀번호가 올바르지 않습니다.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
    }
    
    if (user.is_active === 0) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(403).json({ error: '비활성화된 계정입니다.' });
      }
      return res.redirect(`/coop-login.html?error=비활성화된 계정입니다.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
    }
    
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.redirect(`/coop-login.html?error=아이디 또는 비밀번호가 올바르지 않습니다.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
    }
    
    req.session.coopUser = { id: user.id, username: user.username, is_admin: !!user.is_admin };
    
    // JSON 요청인 경우 JSON 응답
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ 
        success: true, 
        message: '로그인 성공',
        user: {
          id: user.id,
          username: user.username,
          isAdmin: !!user.is_admin
        }
      });
    }
    
    // HTML 폼 요청인 경우 리다이렉트
    res.redirect(returnTo || '/nanum.html');
  } catch (error) {
    console.error('[COOP LOGIN ERROR]', error);
    console.error('[COOP LOGIN ERROR] Stack:', error.stack);
    console.error('[COOP LOGIN ERROR] Username:', username);
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(500).json({ error: '로그인 중 오류가 발생했습니다.', details: process.env.NODE_ENV === 'production' ? undefined : error.message });
    }
    return res.redirect(`/coop-login.html?error=로그인 중 오류가 발생했습니다.&returnTo=${encodeURIComponent(returnTo || '/nanum.html')}`);
  }
});
app.post('/coop/logout', (req, res) => {
  req.session.coopUser = null;
  if (req.headers['content-type']?.includes('application/json')) {
    return res.json({ success: true, message: '로그아웃되었습니다.' });
  }
  res.redirect('/nanum.html');
});

// Coop 회원가입
app.post('/coop/register', async (req, res) => {
  const { username, password, name, email, phone, address } = req.body;
  if (!username || !password) {
    return res.redirect('/coop-register.html?error=아이디와 비밀번호를 입력하세요.');
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run(
      'INSERT INTO coop_users (username, password_hash, name, email, phone, address) VALUES (?,?,?,?,?,?)',
      [username.trim(), hash, name || null, email || null, phone || null, address || null]
    );
    res.redirect('/coop-login.html?success=회원가입이 완료되었습니다.');
  } catch (e) {
    res.redirect('/coop-register.html?error=이미 존재하는 아이디이거나 오류가 발생했습니다.');
  }
});

// Coop 사용자 세션 정보 API
app.get('/api/coop/user', (req, res) => {
  if (req.session.coopUser) {
    res.json({ 
      loggedIn: true, 
      username: req.session.coopUser.username,
      isAdmin: !!req.session.coopUser.is_admin 
    });
  } else {
    res.json({ loggedIn: false, username: null, isAdmin: false });
  }
});

// Coop 아이디 중복확인 API
app.post('/api/coop/check-username', async (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length < 3) {
    return res.json({ available: false, message: '아이디는 3자 이상이어야 합니다.' });
  }
  try {
    const user = await db.get('SELECT id FROM coop_users WHERE username = ?', [username.trim()]);
    if (user) {
      res.json({ available: false, message: '이미 사용 중인 아이디입니다.' });
    } else {
      res.json({ available: true, message: '사용 가능한 아이디입니다.' });
    }
  } catch (error) {
    console.error('Error checking username:', error);
    res.status(500).json({ available: false, message: '확인 중 오류가 발생했습니다.' });
  }
});

// Coop 관리자 체크 API
app.get('/api/coop/check-admin', (req, res) => {
  res.json({ isAdmin: !!req.session.coopUser?.is_admin });
});

// Coop 관리자 미들웨어
function requireCoopLogin(req, res, next) {
  if (!req.session.coopUser) {
    return res.redirect(`/coop-login.html?returnTo=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
}
function requireCoopAdmin(req, res, next) {
  if (!req.session.coopUser?.is_admin) return res.status(403).send('관리자만 접근 가능합니다.');
  next();
}

// ========== 한국장애인스크린파크골프협회 (Golf) 라우트 ==========
// Golf 로그인
app.get('/golf/login', (req, res) => {
  const returnTo = req.query.returnTo || '/aboutgolf.html';
  res.redirect(`/golf-login.html?returnTo=${encodeURIComponent(returnTo)}`);
});
app.post('/golf/login', async (req, res) => {
  const { username, password, returnTo } = req.body;
  
  // 데이터베이스 연결 확인
  if (!db) {
    console.error('[GOLF LOGIN ERROR] Database not initialized');
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(503).json({ error: '서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.' });
    }
    return res.redirect(`/golf-login.html?error=서버가 준비되지 않았습니다. 잠시 후 다시 시도해주세요.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
  }
  
  if (!username || !password) {
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    return res.redirect(`/golf-login.html?error=아이디와 비밀번호를 입력하세요.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
  }
  
  try {
    const user = await db.get('SELECT * FROM golf_users WHERE username = ?', [username]);
    if (!user) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.redirect(`/golf-login.html?error=아이디 또는 비밀번호가 올바르지 않습니다.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
    }
    
    if (user.is_active === 0) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(403).json({ error: '비활성화된 계정입니다.' });
      }
      return res.redirect(`/golf-login.html?error=비활성화된 계정입니다.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
    }
    
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      }
      return res.redirect(`/golf-login.html?error=아이디 또는 비밀번호가 올바르지 않습니다.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
    }
    
    req.session.golfUser = { id: user.id, username: user.username, is_admin: !!user.is_admin };
    
    // JSON 요청인 경우 JSON 응답
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ 
        success: true, 
        message: '로그인 성공',
        user: {
          id: user.id,
          username: user.username,
          isAdmin: !!user.is_admin
        }
      });
    }
    
    // HTML 폼 요청인 경우 리다이렉트
    res.redirect(returnTo || '/aboutgolf.html');
  } catch (error) {
    console.error('[GOLF LOGIN ERROR]', error);
    console.error('[GOLF LOGIN ERROR] Stack:', error.stack);
    console.error('[GOLF LOGIN ERROR] Username:', username);
    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(500).json({ error: '로그인 중 오류가 발생했습니다.', details: process.env.NODE_ENV === 'production' ? undefined : error.message });
    }
    return res.redirect(`/golf-login.html?error=로그인 중 오류가 발생했습니다.&returnTo=${encodeURIComponent(returnTo || '/aboutgolf.html')}`);
  }
});
app.post('/golf/logout', (req, res) => {
  req.session.golfUser = null;
  if (req.headers['content-type']?.includes('application/json')) {
    return res.json({ success: true, message: '로그아웃되었습니다.' });
  }
  res.redirect('/aboutgolf.html');
});

// Golf 회원가입
app.post('/golf/register', async (req, res) => {
  const { username, password, name, email, phone, address } = req.body;
  if (!username || !password) {
    return res.redirect('/golf-register.html?error=아이디와 비밀번호를 입력하세요.');
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run(
      'INSERT INTO golf_users (username, password_hash, name, email, phone, address) VALUES (?,?,?,?,?,?)',
      [username.trim(), hash, name || null, email || null, phone || null, address || null]
    );
    res.redirect('/golf-login.html?success=회원가입이 완료되었습니다.');
  } catch (e) {
    res.redirect('/golf-register.html?error=이미 존재하는 아이디이거나 오류가 발생했습니다.');
  }
});

// Golf 사용자 세션 정보 API
app.get('/api/golf/user', (req, res) => {
  if (req.session.golfUser) {
    res.json({ 
      loggedIn: true, 
      username: req.session.golfUser.username,
      isAdmin: !!req.session.golfUser.is_admin 
    });
  } else {
    res.json({ loggedIn: false, username: null, isAdmin: false });
  }
});

// Golf 아이디 중복확인 API
app.post('/api/golf/check-username', async (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length < 3) {
    return res.json({ available: false, message: '아이디는 3자 이상이어야 합니다.' });
  }
  try {
    const user = await db.get('SELECT id FROM golf_users WHERE username = ?', [username.trim()]);
    if (user) {
      res.json({ available: false, message: '이미 사용 중인 아이디입니다.' });
    } else {
      res.json({ available: true, message: '사용 가능한 아이디입니다.' });
    }
  } catch (error) {
    console.error('Error checking username:', error);
    res.status(500).json({ available: false, message: '확인 중 오류가 발생했습니다.' });
  }
});

// Golf 관리자 체크 API
app.get('/api/golf/check-admin', (req, res) => {
  res.json({ isAdmin: !!req.session.golfUser?.is_admin });
});

// Golf 관리자 미들웨어
function requireGolfLogin(req, res, next) {
  if (!req.session.golfUser) {
    return res.redirect(`/golf-login.html?returnTo=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
}
function requireGolfAdmin(req, res, next) {
  if (!req.session.golfUser?.is_admin) return res.status(403).send('관리자만 접근 가능합니다.');
  next();
}

// 아이디 중복확인 API
app.post('/api/check-username', async (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length < 3) {
    return res.json({ available: false, message: '아이디는 3자 이상이어야 합니다.' });
  }
  try {
    const user = await db.get('SELECT id FROM users WHERE username = ?', [username.trim()]);
    if (user) {
      res.json({ available: false, message: '이미 사용 중인 아이디입니다.' });
    } else {
      res.json({ available: true, message: '사용 가능한 아이디입니다.' });
    }
  } catch (error) {
    console.error('Error checking username:', error);
    res.status(500).json({ available: false, message: '확인 중 오류가 발생했습니다.' });
  }
});

// 비밀번호 찾기 API
app.post('/api/find-password', async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    return res.json({ success: false, message: '아이디와 이메일을 입력해주세요.' });
  }
  try {
    const user = await db.get('SELECT * FROM users WHERE username = ? AND email = ?', [username.trim(), email.trim()]);
    if (!user) {
      return res.json({ success: false, message: '일치하는 정보를 찾을 수 없습니다.' });
    }
    
    // 임시 비밀번호 생성
    const tempPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(tempPassword, 10);
    
    // 비밀번호 업데이트
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, user.id]);
    
    // 실제 이메일 전송 기능은 구현되지 않았으므로, 여기서는 콘솔에 출력
    console.log(`[비밀번호 찾기] 사용자: ${username}, 임시 비밀번호: ${tempPassword}`);
    
    // 실제 프로덕션에서는 이메일 전송 기능을 구현해야 합니다
    // 예: nodemailer 등을 사용하여 이메일 전송
    
    res.json({ 
      success: true, 
      message: '임시 비밀번호가 이메일로 전송되었습니다. (개발 환경에서는 콘솔을 확인하세요)',
      tempPassword: tempPassword // 개발 환경에서만 반환 (실제로는 제거해야 함)
    });
  } catch (error) {
    console.error('Error finding password:', error);
    res.status(500).json({ success: false, message: '오류가 발생했습니다. 다시 시도해주세요.' });
  }
});

// 관리자 체크 API
app.get('/api/check-admin', (req, res) => {
  res.json({ isAdmin: !!req.session.user?.is_admin });
});

// 후원 신청
app.post('/sponsors', async (req, res) => {
  const { name, phone, email, sponsorType, amount, method, message } = req.body;
  if (!name || !phone || !sponsorType) {
    return res.status(400).json({ error: '필수 항목을 입력해주세요.' });
  }
  try {
    await db.run(
      'INSERT INTO sponsors (name, phone, email, sponsor_type, amount, payment_method, message) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name.trim(), phone.trim(), email?.trim() || null, sponsorType, amount ? parseInt(amount) : null, method || null, message?.trim() || null]
    );
    res.json({ success: true, message: '후원 신청이 완료되었습니다. 감사합니다.' });
  } catch (error) {
    console.error('Error creating sponsor:', error);
    res.status(500).json({ error: '후원 신청 중 오류가 발생했습니다.' });
  }
});

// 관리자용 후원 신청 목록
app.get('/admin/sponsors', requireLogin, requireAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || 'all';
  
  let query = 'SELECT * FROM sponsors';
  let countQuery = 'SELECT COUNT(*) as count FROM sponsors';
  const params = [];
  
  if (status !== 'all') {
    query += ' WHERE status = ?';
    countQuery += ' WHERE status = ?';
    params.push(status);
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const totalCount = await db.get(countQuery, params);
  const totalPages = Math.ceil(totalCount.count / limit);
  
  const sponsors = await db.all(query, [...params, limit, offset]);
  
  res.render('sponsors/index', {
    sponsors,
    currentPage: page,
    totalPages,
    totalCount: totalCount.count,
    currentStatus: status,
    currentUser: req.session.user
  });
});

// 관리자용 후원 신청 상세
app.get('/admin/sponsors/:id', requireLogin, requireAdmin, async (req, res) => {
  const sponsor = await db.get('SELECT * FROM sponsors WHERE id = ?', [req.params.id]);
  if (!sponsor) return res.status(404).send('Not Found');
  res.render('sponsors/detail', { sponsor, currentUser: req.session.user });
});

// 관리자용 후원 신청 상태 변경
app.post('/admin/sponsors/:id/status', requireLogin, requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['pending', 'confirmed', 'completed', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: '유효하지 않은 상태입니다.' });
  }
  await db.run('UPDATE sponsors SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, req.params.id]);
  res.json({ success: true });
});

// 관리자용 후원 신청 삭제
app.post('/admin/sponsors/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  await db.run('DELETE FROM sponsors WHERE id = ?', [req.params.id]);
  res.redirect('/admin/sponsors');
});

// 관리자용 회원 목록
app.get('/admin/users', requireLogin, requireAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || 'all';
  const search = req.query.search || '';
  
  let query = 'SELECT id, username, name, email, phone, is_admin, is_active, created_at FROM users';
  let countQuery = 'SELECT COUNT(*) as count FROM users';
  const params = [];
  const conditions = [];
  
  if (status !== 'all') {
    if (status === 'active') {
      conditions.push('is_active = 1');
    } else if (status === 'inactive') {
      conditions.push('is_active = 0');
    } else if (status === 'admin') {
      conditions.push('is_admin = 1');
    }
  }
  
  if (search) {
    conditions.push('(username LIKE ? OR name LIKE ? OR email LIKE ? OR phone LIKE ?)');
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm, searchTerm, searchTerm);
  }
  
  if (conditions.length > 0) {
    const whereClause = ' WHERE ' + conditions.join(' AND ');
    query += whereClause;
    countQuery += whereClause;
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const totalCount = await db.get(countQuery, params);
  const totalPages = Math.ceil(totalCount.count / limit);
  
  const users = await db.all(query, [...params, limit, offset]);
  
  res.render('admin/users/index', {
    users,
    currentPage: page,
    totalPages,
    totalCount: totalCount.count,
    currentStatus: status,
    searchQuery: search,
    currentUser: req.session.user
  });
});

// 관리자용 회원 상세
app.get('/admin/users/:id', requireLogin, requireAdmin, async (req, res) => {
  const user = await db.get('SELECT id, username, name, email, phone, birthdate, gender, is_admin, is_active, created_at FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).send('Not Found');
  
  // 회원이 작성한 게시글 수
  const postCount = await db.get('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', [req.params.id]);
  user.postCount = postCount.count;
  
  res.render('admin/users/detail', { user, currentUser: req.session.user });
});

// 관리자용 회원 활성상태 변경
app.post('/admin/users/:id/status', requireLogin, requireAdmin, async (req, res) => {
  const { is_active } = req.body;
  const activeValue = is_active === 'true' || is_active === '1' ? 1 : 0;
  await db.run('UPDATE users SET is_active = ? WHERE id = ?', [activeValue, req.params.id]);
  res.json({ success: true });
});

// 관리자용 회원 정보 수정
app.post('/admin/users/:id', requireLogin, requireAdmin, async (req, res) => {
  const { username, name, email, phone } = req.body;
  const userId = parseInt(req.params.id);
  const isSelf = userId === req.session.user.id;
  
  // 아이디 변경 시 중복 확인
  if (username) {
    const existingUser = await db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username.trim(), userId]);
    if (existingUser) {
      return res.status(400).json({ error: '이미 사용 중인 아이디입니다.' });
    }
    
    if (username.trim().length < 3) {
      return res.status(400).json({ error: '아이디는 3자 이상이어야 합니다.' });
    }
    
    // 기존 아이디 확인
    const currentUser = await db.get('SELECT username FROM users WHERE id = ?', [userId]);
    const usernameChanged = currentUser && currentUser.username !== username.trim();
    
    await db.run('UPDATE users SET username = ?, name = ?, email = ?, phone = ? WHERE id = ?', 
      [username.trim(), name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
    
    // 자기 자신의 아이디를 변경한 경우 세션 업데이트
    if (isSelf && usernameChanged) {
      req.session.user.username = username.trim();
    }
  } else {
    await db.run('UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?', 
      [name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
  }
  
  res.json({ success: true });
});

// 관리자용 회원 비밀번호 초기화
app.post('/admin/users/:id/reset-password', requireLogin, requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.params.id]);
  res.json({ success: true });
});

// 관리자용 회원 삭제
app.post('/admin/users/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  // 자기 자신은 삭제 불가
  if (parseInt(req.params.id) === req.session.user.id) {
    return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다.' });
  }
  await db.run('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.redirect('/admin/users');
});

// 관리자용 사이트 설정 (메인 페이지 이미지 관리)
app.get('/admin/settings', requireLogin, requireAdmin, async (req, res) => {
  try {
    const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'hero_image'");
    const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'about_image'");
    
    // 협회알림 목록도 함께 가져오기
    let announcements = [];
    try {
      announcements = await db.all(
        'SELECT * FROM announcements ORDER BY display_order ASC, created_at DESC'
      ) || [];
    } catch (error) {
      console.error('Error fetching announcements:', error);
      announcements = [];
    }
    
    // 공지사항 목록도 함께 가져오기
    let notices = [];
    try {
      notices = await db.all(
        'SELECT * FROM notices ORDER BY display_order ASC, created_at DESC'
      ) || [];
    } catch (error) {
      console.error('Error fetching notices:', error);
      notices = [];
    }
    
    res.render('admin/settings/index', {
      heroImage: heroImage?.setting_value || 'img/hero.jpg',
      aboutImage: aboutImage?.setting_value || 'img/0009.jpg',
      announcements: announcements,
      notices: notices,
      currentUser: req.session.user
    });
  } catch (error) {
    console.error('Error in /admin/settings:', error);
    res.status(500).send('서버 오류가 발생했습니다.');
  }
});

// 관리자용 사이트 설정 업데이트
app.post('/admin/settings/hero-image', requireLogin, requireAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'hero_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'hero_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('hero_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

app.post('/admin/settings/about-image', requireLogin, requireAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'about_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'about_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('about_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

// 사이트 설정 API (메인 페이지에서 사용)
app.get('/api/site-settings', async (req, res) => {
  const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'hero_image'");
  const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'about_image'");
  
  res.json({
    heroImage: heroImage?.setting_value || 'img/hero.jpg',
    aboutImage: aboutImage?.setting_value || 'img/0009.jpg'
  });
});

// 협회알림 API
app.get('/api/announcements', async (req, res) => {
  try {
    const announcements = await db.all(
      'SELECT * FROM announcements WHERE is_active = 1 ORDER BY display_order ASC, created_at DESC'
    );
    res.json({ announcements: announcements || [] });
  } catch (error) {
    console.error('Error fetching announcements:', error);
    res.status(500).json({ error: '협회알림을 불러오는 중 오류가 발생했습니다.', announcements: [] });
  }
});

// 공지사항 API
app.get('/api/notices', async (req, res) => {
  try {
    const notices = await db.all(
      'SELECT * FROM notices WHERE is_active = 1 ORDER BY display_order ASC, created_at DESC LIMIT 5'
    );
    res.json({ notices: notices || [] });
  } catch (error) {
    console.error('Error fetching notices:', error);
    res.status(500).json({ error: '공지사항을 불러오는 중 오류가 발생했습니다.', notices: [] });
  }
});

// 관리자용 협회알림 목록
app.get('/admin/announcements', requireLogin, requireAdmin, async (req, res) => {
  try {
    const announcements = await db.all(
      'SELECT * FROM announcements ORDER BY display_order ASC, created_at DESC'
    );
    res.render('admin/announcements/index', {
      announcements: announcements || [],
      currentUser: req.session.user
    });
  } catch (error) {
    console.error('Error fetching announcements:', error);
    res.render('admin/announcements/index', {
      announcements: [],
      currentUser: req.session.user
    });
  }
});

// 관리자용 협회알림 생성
app.post('/admin/announcements', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { content, display_order } = req.body;
    if (!content?.trim()) {
      return res.status(400).json({ error: '내용을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    await db.run(
      'INSERT INTO announcements (content, display_order) VALUES (?, ?)',
      [content.trim(), order]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error creating announcement:', error);
    res.status(500).json({ error: '협회알림 생성 중 오류가 발생했습니다.' });
  }
});

// 관리자용 협회알림 수정
app.put('/admin/announcements/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { content, display_order, is_active } = req.body;
    
    if (!content?.trim()) {
      return res.status(400).json({ error: '내용을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    const active = is_active === 'true' || is_active === 1 || is_active === '1' ? 1 : 0;
    
    await db.run(
      'UPDATE announcements SET content = ?, display_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [content.trim(), order, active, id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating announcement:', error);
    res.status(500).json({ error: '협회알림 수정 중 오류가 발생했습니다.' });
  }
});

// 관리자용 협회알림 삭제
app.delete('/admin/announcements/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run('DELETE FROM announcements WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting announcement:', error);
    res.status(500).json({ error: '협회알림 삭제 중 오류가 발생했습니다.' });
  }
});

// 관리자용 공지사항 생성
app.post('/admin/notices', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { title, icon_class, icon_color, notice_date, link, display_order } = req.body;
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    await db.run(
      'INSERT INTO notices (title, icon_class, icon_color, notice_date, link, display_order) VALUES (?, ?, ?, ?, ?, ?)',
      [title.trim(), icon_class?.trim() || null, icon_color?.trim() || null, notice_date?.trim() || null, link?.trim() || null, order]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error creating notice:', error);
    res.status(500).json({ error: '공지사항 생성 중 오류가 발생했습니다.' });
  }
});

// 관리자용 공지사항 수정
app.put('/admin/notices/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, icon_class, icon_color, notice_date, link, display_order, is_active } = req.body;
    
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    const active = is_active === 'true' || is_active === 1 || is_active === '1' ? 1 : 0;
    
    await db.run(
      'UPDATE notices SET title = ?, icon_class = ?, icon_color = ?, notice_date = ?, link = ?, display_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title.trim(), icon_class?.trim() || null, icon_color?.trim() || null, notice_date?.trim() || null, link?.trim() || null, order, active, id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating notice:', error);
    res.status(500).json({ error: '공지사항 수정 중 오류가 발생했습니다.' });
  }
});

// 관리자용 공지사항 삭제
app.delete('/admin/notices/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run('DELETE FROM notices WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting notice:', error);
    res.status(500).json({ error: '공지사항 삭제 중 오류가 발생했습니다.' });
  }
});

// ========== 전국장애인나눔협동조합 관리자 페이지 ==========
// Coop 관리자 대시보드
app.get('/coop/admin', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const userCount = await db.get('SELECT COUNT(*) as count FROM coop_users');
  const adminCount = await db.get('SELECT COUNT(*) as count FROM coop_users WHERE is_admin = 1');
  res.render('admin/users/index', {
    users: [],
    currentPage: 1,
    totalPages: 1,
    totalCount: userCount.count,
    currentStatus: 'all',
    searchQuery: '',
    currentUser: req.session.coopUser,
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합',
    adminCount: adminCount.count
  });
});

// Coop 관리자용 회원 목록
app.get('/coop/admin/users', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || 'all';
  const search = req.query.search || '';
  
  let query = 'SELECT id, username, name, email, phone, is_admin, is_active, created_at FROM coop_users';
  let countQuery = 'SELECT COUNT(*) as count FROM coop_users';
  const params = [];
  const conditions = [];
  
  if (status !== 'all') {
    if (status === 'active') {
      conditions.push('is_active = 1');
    } else if (status === 'inactive') {
      conditions.push('is_active = 0');
    } else if (status === 'admin') {
      conditions.push('is_admin = 1');
    }
  }
  
  if (search) {
    conditions.push('(username LIKE ? OR name LIKE ? OR email LIKE ? OR phone LIKE ?)');
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm, searchTerm, searchTerm);
  }
  
  if (conditions.length > 0) {
    const whereClause = ' WHERE ' + conditions.join(' AND ');
    query += whereClause;
    countQuery += whereClause;
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const totalCount = await db.get(countQuery, params);
  const totalPages = Math.ceil(totalCount.count / limit);
  
  const users = await db.all(query, [...params, limit, offset]);
  
  res.render('admin/users/index', {
    users,
    currentPage: page,
    totalPages,
    totalCount: totalCount.count,
    currentStatus: status,
    searchQuery: search,
    currentUser: req.session.coopUser,
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합'
  });
});

// Coop 관리자용 회원 상세
app.get('/coop/admin/users/:id', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const user = await db.get('SELECT id, username, name, email, phone, birthdate, gender, is_admin, is_active, created_at FROM coop_users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).send('Not Found');
  
  res.render('admin/users/detail', { 
    user, 
    currentUser: req.session.coopUser,
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합'
  });
});

// Coop 관리자용 회원 활성상태 변경
app.post('/coop/admin/users/:id/status', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const { is_active } = req.body;
  const activeValue = is_active === 'true' || is_active === '1' ? 1 : 0;
  await db.run('UPDATE coop_users SET is_active = ? WHERE id = ?', [activeValue, req.params.id]);
  res.json({ success: true });
});

// Coop 관리자용 회원 정보 수정
app.post('/coop/admin/users/:id', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const { username, name, email, phone } = req.body;
  const userId = parseInt(req.params.id);
  const isSelf = userId === req.session.coopUser.id;
  
  // 아이디 변경 시 중복 확인
  if (username) {
    const existingUser = await db.get('SELECT id FROM coop_users WHERE username = ? AND id != ?', [username.trim(), userId]);
    if (existingUser) {
      return res.status(400).json({ error: '이미 사용 중인 아이디입니다.' });
    }
    
    if (username.trim().length < 3) {
      return res.status(400).json({ error: '아이디는 3자 이상이어야 합니다.' });
    }
    
    // 기존 아이디 확인
    const currentUser = await db.get('SELECT username FROM coop_users WHERE id = ?', [userId]);
    const usernameChanged = currentUser && currentUser.username !== username.trim();
    
    await db.run('UPDATE coop_users SET username = ?, name = ?, email = ?, phone = ? WHERE id = ?', 
      [username.trim(), name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
    
    // 자기 자신의 아이디를 변경한 경우 세션 업데이트
    if (isSelf && usernameChanged) {
      req.session.coopUser.username = username.trim();
    }
  } else {
    await db.run('UPDATE coop_users SET name = ?, email = ?, phone = ? WHERE id = ?', 
      [name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
  }
  
  res.json({ success: true });
});

// Coop 관리자용 회원 비밀번호 초기화
app.post('/coop/admin/users/:id/reset-password', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await db.run('UPDATE coop_users SET password_hash = ? WHERE id = ?', [hash, req.params.id]);
  res.json({ success: true });
});

// Coop 관리자용 회원 삭제
app.post('/coop/admin/users/:id/delete', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.session.coopUser.id) {
    return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다.' });
  }
  await db.run('DELETE FROM coop_users WHERE id = ?', [req.params.id]);
  res.redirect('/coop/admin/users');
});

// ========== 전국장애인나눔협동조합 조합원 가입 신청 ==========
// 조합원 가입 신청 제출
app.post('/coop/accession', upload.array('documents', 10), async (req, res) => {
  try {
    const { name, birthdate, phone, address, email, disabilityType, message } = req.body;
    
    // 필수 항목 검증
    if (!name?.trim() || !birthdate?.trim() || !phone?.trim() || !address?.trim() || !email?.trim() || !disabilityType?.trim()) {
      return res.status(400).json({ error: '필수 항목을 모두 입력해주세요.\n\n필수 항목: 성함, 생년월일, 연락처, 주소, 이메일, 장애유형 및 등급' });
    }
    
    // 신청서 저장
    const result = await db.run(
      'INSERT INTO coop_accessions (name, birthdate, phone, address, email, disability_type, message) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name.trim(), birthdate.trim(), phone.trim(), address.trim(), email.trim(), disabilityType.trim(), message?.trim() || null]
    );
    const accessionId = result.lastID;
    
    // 첨부 파일 저장
    if (req.files && req.files.length > 0) {
      for (let i = 0; i < req.files.length; i++) {
        const file = req.files[i];
        const filePath = `/public/uploads/${file.filename}`;
        await db.run(
          'INSERT INTO coop_accession_documents (accession_id, file_path, file_name, file_size, display_order) VALUES (?, ?, ?, ?, ?)',
          [accessionId, filePath, file.originalname, file.size, i]
        );
      }
    }
    
    res.json({ success: true, message: '조합원 가입 신청이 완료되었습니다.\n담당자가 확인 후 연락을 드리겠습니다. 감사합니다!' });
  } catch (error) {
    console.error('Error creating accession:', error);
    res.status(500).json({ error: '신청 중 오류가 발생했습니다.' });
  }
});

// Coop 관리자용 조합원 가입 신청 목록
app.get('/coop/admin/accessions', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || 'all';
  
  let query = 'SELECT * FROM coop_accessions';
  let countQuery = 'SELECT COUNT(*) as count FROM coop_accessions';
  const params = [];
  
  if (status !== 'all') {
    query += ' WHERE status = ?';
    countQuery += ' WHERE status = ?';
    params.push(status);
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const totalCount = await db.get(countQuery, params);
  const totalPages = Math.ceil(totalCount.count / limit);
  
  const accessions = await db.all(query, [...params, limit, offset]);
  
  // 각 신청서의 첨부 파일 수 가져오기
  for (const accession of accessions) {
    const docCount = await db.get('SELECT COUNT(*) as count FROM coop_accession_documents WHERE accession_id = ?', [accession.id]);
    accession.documentCount = docCount.count;
  }
  
  res.render('admin/accessions/index', {
    accessions,
    currentPage: page,
    totalPages,
    totalCount: totalCount.count,
    currentStatus: status,
    currentUser: req.session.coopUser,
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합'
  });
});

// Coop 관리자용 조합원 가입 신청 상세
app.get('/coop/admin/accessions/:id', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const accession = await db.get('SELECT * FROM coop_accessions WHERE id = ?', [req.params.id]);
  if (!accession) return res.status(404).send('Not Found');
  
  const documents = await db.all(
    'SELECT * FROM coop_accession_documents WHERE accession_id = ? ORDER BY display_order ASC',
    [req.params.id]
  );
  
  res.render('admin/accessions/detail', {
    accession,
    documents: documents || [],
    currentUser: req.session.coopUser,
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합'
  });
});

// Coop 관리자용 조합원 가입 신청 상태 변경
app.post('/coop/admin/accessions/:id/status', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['pending', 'reviewing', 'approved', 'rejected', 'completed'].includes(status)) {
    return res.status(400).json({ error: '유효하지 않은 상태입니다.' });
  }
  await db.run('UPDATE coop_accessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, req.params.id]);
  res.json({ success: true });
});

// Coop 관리자용 조합원 가입 신청 삭제
app.post('/coop/admin/accessions/:id/delete', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  const accession = await db.get('SELECT * FROM coop_accessions WHERE id = ?', [req.params.id]);
  if (!accession) return res.status(404).json({ error: '신청서를 찾을 수 없습니다.' });
  
  // 첨부 파일 삭제
  const documents = await db.all('SELECT file_path FROM coop_accession_documents WHERE accession_id = ?', [req.params.id]);
  for (const doc of documents) {
    if (doc.file_path && doc.file_path.startsWith('/public/uploads/')) {
      const filePath = path.join(__dirname, doc.file_path);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
  }
  
  await db.run('DELETE FROM coop_accessions WHERE id = ?', [req.params.id]);
  res.redirect('/coop/admin/accessions');
});

// ========== 전국장애인나눔협동조합 태양광 갤러리 관리 ==========
// 태양광 갤러리 목록 API (공개)
app.get('/api/coop/solar-gallery', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 6;
    const offset = (page - 1) * limit;
    
    const totalCount = await db.get('SELECT COUNT(*) as count FROM coop_solar_gallery WHERE is_active = 1');
    const totalItems = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalItems / limit);
    
    const items = await db.all(
      'SELECT * FROM coop_solar_gallery WHERE is_active = 1 ORDER BY display_order ASC, created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );
    
    res.json({ 
      items: items || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalItems: totalItems,
        limit: limit,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching solar gallery:', error);
    res.status(500).json({ error: '갤러리를 불러오는 중 오류가 발생했습니다.', items: [], pagination: { currentPage: 1, totalPages: 1, totalItems: 0, limit: 6, hasNext: false, hasPrev: false } });
  }
});

// Coop 관리자용 태양광 갤러리 관리 페이지
app.get('/coop/admin/solar-gallery', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  try {
    const items = await db.all(
      'SELECT * FROM coop_solar_gallery ORDER BY display_order ASC, created_at DESC'
    );
    res.render('admin/solar-gallery/index', {
      items: items || [],
      currentUser: req.session.coopUser,
      orgType: 'coop',
      orgName: '전국장애인나눔협동조합'
    });
  } catch (error) {
    console.error('Error fetching solar gallery:', error);
    res.render('admin/solar-gallery/index', {
      items: [],
      currentUser: req.session.coopUser,
      orgType: 'coop',
      orgName: '전국장애인나눔협동조합'
    });
  }
});

// Coop 관리자용 태양광 갤러리 이미지 업로드
app.post('/coop/admin/solar-gallery', requireCoopLogin, requireCoopAdmin, upload.single('image'), async (req, res) => {
  try {
    const { title, status_badge, date_text, display_order } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
    }
    
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const imagePath = `/public/uploads/${req.file.filename}`;
    const order = display_order ? parseInt(display_order) : 0;
    
    await db.run(
      'INSERT INTO coop_solar_gallery (image_path, title, status_badge, date_text, display_order) VALUES (?, ?, ?, ?, ?)',
      [imagePath, title.trim(), status_badge?.trim() || null, date_text?.trim() || null, order]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error uploading solar gallery image:', error);
    res.status(500).json({ error: '이미지 업로드 중 오류가 발생했습니다.' });
  }
});

// Coop 관리자용 태양광 갤러리 항목 수정
app.put('/coop/admin/solar-gallery/:id', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, status_badge, date_text, display_order, is_active } = req.body;
    
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    const active = is_active === 'true' || is_active === 1 || is_active === '1' ? 1 : 0;
    
    await db.run(
      'UPDATE coop_solar_gallery SET title = ?, status_badge = ?, date_text = ?, display_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title.trim(), status_badge?.trim() || null, date_text?.trim() || null, order, active, id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating solar gallery item:', error);
    res.status(500).json({ error: '수정 중 오류가 발생했습니다.' });
  }
});

// Coop 관리자용 태양광 갤러리 항목 삭제
app.delete('/coop/admin/solar-gallery/:id', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await db.get('SELECT * FROM coop_solar_gallery WHERE id = ?', [id]);
    
    if (!item) {
      return res.status(404).json({ error: '항목을 찾을 수 없습니다.' });
    }
    
    // 이미지 파일 삭제
    if (item.image_path && item.image_path.startsWith('/public/uploads/')) {
      const filePath = path.join(__dirname, item.image_path);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    
    await db.run('DELETE FROM coop_solar_gallery WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting solar gallery item:', error);
    res.status(500).json({ error: '삭제 중 오류가 발생했습니다.' });
  }
});

// ========== 한국장애인스크린파크골프협회 관리자 페이지 ==========
// Golf 관리자 대시보드
app.get('/golf/admin', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const userCount = await db.get('SELECT COUNT(*) as count FROM golf_users');
  const adminCount = await db.get('SELECT COUNT(*) as count FROM golf_users WHERE is_admin = 1');
  res.render('admin/users/index', {
    users: [],
    currentPage: 1,
    totalPages: 1,
    totalCount: userCount.count,
    currentStatus: 'all',
    searchQuery: '',
    currentUser: req.session.golfUser,
    orgType: 'golf',
    orgName: '한국장애인스크린파크골프협회',
    adminCount: adminCount.count
  });
});

// Golf 관리자용 회원 목록
app.get('/golf/admin/users', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || 'all';
  const search = req.query.search || '';
  
  let query = 'SELECT id, username, name, email, phone, is_admin, is_active, created_at FROM golf_users';
  let countQuery = 'SELECT COUNT(*) as count FROM golf_users';
  const params = [];
  const conditions = [];
  
  if (status !== 'all') {
    if (status === 'active') {
      conditions.push('is_active = 1');
    } else if (status === 'inactive') {
      conditions.push('is_active = 0');
    } else if (status === 'admin') {
      conditions.push('is_admin = 1');
    }
  }
  
  if (search) {
    conditions.push('(username LIKE ? OR name LIKE ? OR email LIKE ? OR phone LIKE ?)');
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm, searchTerm, searchTerm);
  }
  
  if (conditions.length > 0) {
    const whereClause = ' WHERE ' + conditions.join(' AND ');
    query += whereClause;
    countQuery += whereClause;
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const totalCount = await db.get(countQuery, params);
  const totalPages = Math.ceil(totalCount.count / limit);
  
  const users = await db.all(query, [...params, limit, offset]);
  
  res.render('admin/users/index', {
    users,
    currentPage: page,
    totalPages,
    totalCount: totalCount.count,
    currentStatus: status,
    searchQuery: search,
    currentUser: req.session.golfUser,
    orgType: 'golf',
    orgName: '한국장애인스크린파크골프협회'
  });
});

// Golf 관리자용 회원 상세
app.get('/golf/admin/users/:id', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const user = await db.get('SELECT id, username, name, email, phone, birthdate, gender, is_admin, is_active, created_at FROM golf_users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).send('Not Found');
  
  res.render('admin/users/detail', { 
    user, 
    currentUser: req.session.golfUser,
    orgType: 'golf',
    orgName: '한국장애인스크린파크골프협회'
  });
});

// Golf 관리자용 회원 활성상태 변경
app.post('/golf/admin/users/:id/status', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const { is_active } = req.body;
  const activeValue = is_active === 'true' || is_active === '1' ? 1 : 0;
  await db.run('UPDATE golf_users SET is_active = ? WHERE id = ?', [activeValue, req.params.id]);
  res.json({ success: true });
});

// Golf 관리자용 회원 정보 수정
app.post('/golf/admin/users/:id', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const { username, name, email, phone } = req.body;
  const userId = parseInt(req.params.id);
  const isSelf = userId === req.session.golfUser.id;
  
  // 아이디 변경 시 중복 확인
  if (username) {
    const existingUser = await db.get('SELECT id FROM golf_users WHERE username = ? AND id != ?', [username.trim(), userId]);
    if (existingUser) {
      return res.status(400).json({ error: '이미 사용 중인 아이디입니다.' });
    }
    
    if (username.trim().length < 3) {
      return res.status(400).json({ error: '아이디는 3자 이상이어야 합니다.' });
    }
    
    // 기존 아이디 확인
    const currentUser = await db.get('SELECT username FROM golf_users WHERE id = ?', [userId]);
    const usernameChanged = currentUser && currentUser.username !== username.trim();
    
    await db.run('UPDATE golf_users SET username = ?, name = ?, email = ?, phone = ? WHERE id = ?', 
      [username.trim(), name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
    
    // 자기 자신의 아이디를 변경한 경우 세션 업데이트
    if (isSelf && usernameChanged) {
      req.session.golfUser.username = username.trim();
    }
  } else {
    await db.run('UPDATE golf_users SET name = ?, email = ?, phone = ? WHERE id = ?', 
      [name?.trim() || null, email?.trim() || null, phone?.trim() || null, userId]);
  }
  
  res.json({ success: true });
});

// Golf 관리자용 회원 비밀번호 초기화
app.post('/golf/admin/users/:id/reset-password', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await db.run('UPDATE golf_users SET password_hash = ? WHERE id = ?', [hash, req.params.id]);
  res.json({ success: true });
});

// Golf 관리자용 회원 삭제
app.post('/golf/admin/users/:id/delete', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.session.golfUser.id) {
    return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다.' });
  }
  await db.run('DELETE FROM golf_users WHERE id = ?', [req.params.id]);
  res.redirect('/golf/admin/users');
});

// ========== 전국장애인나눔협동조합 사이트 설정 ==========
// Coop 관리자용 사이트 설정 페이지
app.get('/coop/admin/settings', requireCoopLogin, requireCoopAdmin, async (req, res) => {
  try {
    const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'coop_hero_image'");
    const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'coop_about_image'");
    
    res.render('admin/settings/coop', {
      heroImage: heroImage?.setting_value || 'img/coop-hero.jpg',
      aboutImage: aboutImage?.setting_value || 'img/coop-4.png',
      currentUser: req.session.coopUser,
      orgType: 'coop',
      orgName: '전국장애인나눔협동조합'
    });
  } catch (error) {
    console.error('Error in /coop/admin/settings:', error);
    res.status(500).send('서버 오류가 발생했습니다.');
  }
});

// Coop 관리자용 Hero 이미지 업로드
app.post('/coop/admin/settings/hero-image', requireCoopLogin, requireCoopAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'coop_hero_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'coop_hero_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('coop_hero_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

// Coop 관리자용 About 이미지 업로드
app.post('/coop/admin/settings/about-image', requireCoopLogin, requireCoopAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'coop_about_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'coop_about_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('coop_about_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

// Coop Hero 이미지 API (공개)
app.get('/api/coop/hero-image', async (req, res) => {
  try {
    const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'coop_hero_image'");
    res.json({
      imagePath: heroImage?.setting_value || 'img/coop-hero.jpg'
    });
  } catch (error) {
    console.error('Error fetching coop hero image:', error);
    res.json({ imagePath: 'img/coop-hero.jpg' });
  }
});

// Coop About 이미지 API (공개)
app.get('/api/coop/about-image', async (req, res) => {
  try {
    const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'coop_about_image'");
    res.json({
      imagePath: aboutImage?.setting_value || 'img/coop-4.png'
    });
  } catch (error) {
    console.error('Error fetching coop about image:', error);
    res.json({ imagePath: 'img/coop-4.png' });
  }
});

// ========== 한국장애인스크린파크골프협회 사이트 설정 ==========
// Golf 관리자용 사이트 설정 페이지
app.get('/golf/admin/settings', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  try {
    const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'golf_hero_image'");
    const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'golf_about_image'");
    
    res.render('admin/settings/golf', {
      heroImage: heroImage?.setting_value || 'img/golf1.png',
      aboutImage: aboutImage?.setting_value || 'img/golf5.png',
      currentUser: req.session.golfUser,
      orgType: 'golf',
      orgName: '한국장애인스크린파크골프협회'
    });
  } catch (error) {
    console.error('Error in /golf/admin/settings:', error);
    res.status(500).send('서버 오류가 발생했습니다.');
  }
});

// Golf 관리자용 About 이미지 업로드
app.post('/golf/admin/settings/about-image', requireGolfLogin, requireGolfAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'golf_about_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'golf_about_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('golf_about_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

// Golf 관리자용 Hero 이미지 업로드
app.post('/golf/admin/settings/hero-image', requireGolfLogin, requireGolfAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
  }
  
  const imagePath = `/public/uploads/${req.file.filename}`;
  
  // 기존 설정 확인
  const existing = await db.get("SELECT * FROM site_settings WHERE setting_key = 'golf_hero_image'");
  if (existing) {
    // 기존 이미지 파일 삭제
    if (existing.setting_value && existing.setting_value.startsWith('/public/uploads/')) {
      const oldPath = path.join(__dirname, existing.setting_value);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    await db.run("UPDATE site_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = 'golf_hero_image'", [imagePath]);
  } else {
    await db.run("INSERT INTO site_settings (setting_key, setting_value) VALUES ('golf_hero_image', ?)", [imagePath]);
  }
  
  res.json({ success: true, imagePath });
});

// Golf About 이미지 API (공개)
app.get('/api/golf/about-image', async (req, res) => {
  try {
    const aboutImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'golf_about_image'");
    res.json({
      imagePath: aboutImage?.setting_value || 'img/golf5.png'
    });
  } catch (error) {
    console.error('Error fetching golf about image:', error);
    res.json({ imagePath: 'img/golf5.png' });
  }
});

// Golf Hero 이미지 API (공개)
app.get('/api/golf/hero-image', async (req, res) => {
  try {
    const heroImage = await db.get("SELECT setting_value FROM site_settings WHERE setting_key = 'golf_hero_image'");
    res.json({
      imagePath: heroImage?.setting_value || 'img/golf1.png'
    });
  } catch (error) {
    console.error('Error fetching golf hero image:', error);
    res.json({ imagePath: 'img/golf1.png' });
  }
});

// ========== 한국장애인스크린파크골프협회 갤러리 관리 ==========
// Golf 갤러리 목록 API (공개)
app.get('/api/golf/gallery', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 6;
    const offset = (page - 1) * limit;
    
    const totalCount = await db.get('SELECT COUNT(*) as count FROM golf_gallery WHERE is_active = 1');
    const totalItems = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalItems / limit);
    
    const items = await db.all(
      'SELECT * FROM golf_gallery WHERE is_active = 1 ORDER BY display_order ASC, created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );
    
    res.json({ 
      items: items || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalItems: totalItems,
        limit: limit,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching golf gallery:', error);
    res.status(500).json({ error: '갤러리를 불러오는 중 오류가 발생했습니다.', items: [], pagination: { currentPage: 1, totalPages: 1, totalItems: 0, limit: 6, hasNext: false, hasPrev: false } });
  }
});

// Golf 관리자용 갤러리 관리 페이지
app.get('/golf/admin/gallery', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  try {
    const items = await db.all(
      'SELECT * FROM golf_gallery ORDER BY display_order ASC, created_at DESC'
    );
    res.render('admin/gallery/golf', {
      items: items || [],
      currentUser: req.session.golfUser,
      orgType: 'golf',
      orgName: '한국장애인스크린파크골프협회'
    });
  } catch (error) {
    console.error('Error fetching golf gallery:', error);
    res.render('admin/gallery/golf', {
      items: [],
      currentUser: req.session.golfUser,
      orgType: 'golf',
      orgName: '한국장애인스크린파크골프협회'
    });
  }
});

// Golf 관리자용 갤러리 이미지 업로드
app.post('/golf/admin/gallery', requireGolfLogin, requireGolfAdmin, upload.single('image'), async (req, res) => {
  try {
    const { title, status_badge, date_text, display_order } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: '이미지 파일을 업로드해주세요.' });
    }
    
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const imagePath = `/public/uploads/${req.file.filename}`;
    const order = display_order ? parseInt(display_order) : 0;
    
    await db.run(
      'INSERT INTO golf_gallery (image_path, title, status_badge, date_text, display_order) VALUES (?, ?, ?, ?, ?)',
      [imagePath, title.trim(), status_badge?.trim() || null, date_text?.trim() || null, order]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error uploading golf gallery image:', error);
    res.status(500).json({ error: '이미지 업로드 중 오류가 발생했습니다.' });
  }
});

// Golf 관리자용 갤러리 항목 수정
app.put('/golf/admin/gallery/:id', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, status_badge, date_text, display_order, is_active } = req.body;
    
    if (!title?.trim()) {
      return res.status(400).json({ error: '제목을 입력해주세요.' });
    }
    
    const order = display_order ? parseInt(display_order) : 0;
    const active = is_active === 'true' || is_active === 1 || is_active === '1' ? 1 : 0;
    
    await db.run(
      'UPDATE golf_gallery SET title = ?, status_badge = ?, date_text = ?, display_order = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title.trim(), status_badge?.trim() || null, date_text?.trim() || null, order, active, id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating golf gallery item:', error);
    res.status(500).json({ error: '수정 중 오류가 발생했습니다.' });
  }
});

// Golf 관리자용 갤러리 항목 삭제
app.delete('/golf/admin/gallery/:id', requireGolfLogin, requireGolfAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const item = await db.get('SELECT * FROM golf_gallery WHERE id = ?', [id]);
    
    if (!item) {
      return res.status(404).json({ error: '항목을 찾을 수 없습니다.' });
    }
    
    // 이미지 파일 삭제
    if (item.image_path && item.image_path.startsWith('/public/uploads/')) {
      const filePath = path.join(__dirname, item.image_path);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    
    await db.run('DELETE FROM golf_gallery WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting golf gallery item:', error);
    res.status(500).json({ error: '삭제 중 오류가 발생했습니다.' });
  }
});

// ========== 전국장애인나눔협동조합 게시판 라우트 ==========
// Coop 게시판 API
app.get('/api/coop/board', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const notices = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM coop_posts p JOIN coop_users u ON u.id = p.user_id
       WHERE p.category = 'general' AND p.is_notice = 1
       ORDER BY p.created_at DESC`
    );
    
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM coop_posts 
       WHERE category = 'general' AND (is_notice = 0 OR is_notice IS NULL)`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM coop_posts p JOIN coop_users u ON u.id = p.user_id
       WHERE p.category = 'general' AND (p.is_notice = 0 OR p.is_notice IS NULL)
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      notices: notices || [], 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/coop/board:', error);
    res.status(500).json({ error: '게시글을 불러오는 중 오류가 발생했습니다.' });
  }
});

// Coop 자유게시판 API
app.get('/api/coop/board/free', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM coop_posts WHERE category = 'free'`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM coop_posts p JOIN coop_users u ON u.id = p.user_id
       WHERE p.category = 'free'
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/coop/board/free:', error);
    res.status(500).json({ 
      error: '게시글을 불러오는 중 오류가 발생했습니다.',
      posts: [],
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalPosts: 0,
        limit: 10,
        hasNext: false,
        hasPrev: false
      }
    });
  }
});

// Coop 글 작성 페이지
app.get('/coop/new', requireCoopLogin, (req, res) => {
  const category = req.query.category || null;
  let categoryName = '게시판';
  
  if (category === 'free') {
    categoryName = '자유게시판';
  } else if (category === 'general') {
    if (!req.session.coopUser.is_admin) {
      return res.status(403).send('알림게시판은 관리자만 글을 작성할 수 있습니다.');
    }
    categoryName = '알림게시판';
  }
  
  res.render('board/new', { 
    error: null, 
    category: category,
    categoryName: categoryName,
    currentUser: req.session.coopUser,
    orgType: 'coop'
  });
});

// Coop 글 작성 POST
app.post('/coop/posts', requireCoopLogin, upload.array('images', 15), async (req, res) => {
  const { title, content, is_notice, category } = req.body;
  const postCategory = category || 'general';
  
  if (!title?.trim() || !content?.trim()) {
    return res.render('board/new', { 
      error: '제목과 내용을 입력하세요.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : '알림게시판',
      currentUser: req.session.coopUser,
      orgType: 'coop'
    });
  }
  
  if (postCategory === 'general' && !req.session.coopUser.is_admin) {
    return res.render('board/new', { 
      error: '알림게시판은 관리자만 글을 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: '알림게시판',
      currentUser: req.session.coopUser,
      orgType: 'coop'
    });
  }
  
  const isNotice = (is_notice === 'on' || is_notice === '1') ? 1 : 0;
  if (isNotice && !req.session.coopUser.is_admin) {
    return res.render('board/new', { 
      error: '공지사항은 관리자만 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : '알림게시판',
      currentUser: req.session.coopUser,
      orgType: 'coop'
    });
  }
  
  // 게시글 생성 (한국 시간대 명시)
  const kstDateTime = getKSTDateTime();
  const result = await db.run('INSERT INTO coop_posts (user_id, category, title, content, is_notice, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
    req.session.coopUser.id,
    postCategory,
    title.trim(),
    content.trim(),
    isNotice,
    kstDateTime
  ]);
  const postId = result.lastID;
  
  if (req.files && req.files.length > 0) {
    const firstImage = `/public/uploads/${req.files[0].filename}`;
    await db.run('UPDATE coop_posts SET image_path = ? WHERE id = ?', [firstImage, postId]);
    
    for (let i = 0; i < req.files.length; i++) {
      const imagePath = `/public/uploads/${req.files[i].filename}`;
      await db.run(
        'INSERT INTO coop_post_images (post_id, image_path, display_order) VALUES (?, ?, ?)',
        [postId, imagePath, i]
      );
    }
  }
  
  res.redirect('/coop-board.html');
});

// Coop 게시글 상세
app.get('/coop/posts/:id', async (req, res) => {
  const post = await db.get(
    `SELECT p.id, p.title, p.content, p.image_path, p.created_at, p.updated_at, p.is_notice, p.view_count, p.category,
            CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
            u.id as user_id
     FROM coop_posts p JOIN coop_users u ON u.id = p.user_id
     WHERE p.id = ?`,
    [req.params.id]
  );
  
  if (!post) return res.status(404).send('Not Found');
  
  await db.run('UPDATE coop_posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?', [req.params.id]);
  
  let images = await db.all(
    'SELECT id, image_path, display_order FROM coop_post_images WHERE post_id = ? ORDER BY display_order ASC',
    [req.params.id]
  );
  
  if (images.length === 0 && post.image_path) {
    images = [{ id: null, image_path: post.image_path, display_order: 0 }];
  }
  
  const categoryName = post.category === 'free' ? '자유게시판' : (post.category === 'general' ? '알림게시판' : '게시판');
  
  res.render('board/detail', { 
    post, 
    images: images || [], 
    category: post.category,
    categoryName: categoryName,
    categoryRoute: '/coop-board.html',
    orgType: 'coop',
    orgName: '전국장애인나눔협동조합'
  });
});

// ========== 한국장애인스크린파크골프협회 게시판 라우트 ==========
// Golf 게시판 API
app.get('/api/golf/board', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const notices = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM golf_posts p JOIN golf_users u ON u.id = p.user_id
       WHERE p.category = 'general' AND p.is_notice = 1
       ORDER BY p.created_at DESC`
    );
    
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM golf_posts 
       WHERE category = 'general' AND (is_notice = 0 OR is_notice IS NULL)`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM golf_posts p JOIN golf_users u ON u.id = p.user_id
       WHERE p.category = 'general' AND (p.is_notice = 0 OR p.is_notice IS NULL)
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      notices: notices || [], 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/golf/board:', error);
    res.status(500).json({ error: '게시글을 불러오는 중 오류가 발생했습니다.' });
  }
});

// Golf 자유게시판 API
app.get('/api/golf/board/free', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    const totalCount = await db.get(
      `SELECT COUNT(*) as count FROM golf_posts WHERE category = 'free'`
    );
    const totalPosts = totalCount ? totalCount.count : 0;
    const totalPages = Math.ceil(totalPosts / limit);
    
    const posts = await db.all(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, 
              COALESCE(p.view_count, 0) as view_count,
              CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
              u.id as user_id
       FROM golf_posts p JOIN golf_users u ON u.id = p.user_id
       WHERE p.category = 'free'
       ORDER BY p.created_at DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    
    res.json({ 
      posts: posts || [],
      pagination: {
        currentPage: page,
        totalPages: totalPages || 1,
        totalPosts: totalPosts,
        limit: 10,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error in /api/golf/board/free:', error);
    res.status(500).json({ 
      error: '게시글을 불러오는 중 오류가 발생했습니다.',
      posts: [],
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalPosts: 0,
        limit: 10,
        hasNext: false,
        hasPrev: false
      }
    });
  }
});

// Golf 글 작성 페이지
app.get('/golf/new', requireGolfLogin, (req, res) => {
  const category = req.query.category || null;
  let categoryName = '게시판';
  
  if (category === 'free') {
    categoryName = '자유게시판';
  } else if (category === 'general') {
    if (!req.session.golfUser.is_admin) {
      return res.status(403).send('알림게시판은 관리자만 글을 작성할 수 있습니다.');
    }
    categoryName = '알림게시판';
  }
  
  res.render('board/new', { 
    error: null, 
    category: category,
    categoryName: categoryName,
    currentUser: req.session.golfUser,
    orgType: 'golf'
  });
});

// Golf 글 작성 POST
app.post('/golf/posts', requireGolfLogin, upload.array('images', 15), async (req, res) => {
  const { title, content, is_notice, category } = req.body;
  const postCategory = category || 'general';
  
  if (!title?.trim() || !content?.trim()) {
    return res.render('board/new', { 
      error: '제목과 내용을 입력하세요.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : '알림게시판',
      currentUser: req.session.golfUser,
      orgType: 'golf'
    });
  }
  
  if (postCategory === 'general' && !req.session.golfUser.is_admin) {
    return res.render('board/new', { 
      error: '알림게시판은 관리자만 글을 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: '알림게시판',
      currentUser: req.session.golfUser,
      orgType: 'golf'
    });
  }
  
  const isNotice = (is_notice === 'on' || is_notice === '1') ? 1 : 0;
  if (isNotice && !req.session.golfUser.is_admin) {
    return res.render('board/new', { 
      error: '공지사항은 관리자만 작성할 수 있습니다.', 
      category: postCategory,
      categoryName: postCategory === 'free' ? '자유게시판' : '알림게시판',
      currentUser: req.session.golfUser,
      orgType: 'golf'
    });
  }
  
  // 게시글 생성 (한국 시간대 명시)
  const kstDateTime = getKSTDateTime();
  const result = await db.run('INSERT INTO golf_posts (user_id, category, title, content, is_notice, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
    req.session.golfUser.id,
    postCategory,
    title.trim(),
    content.trim(),
    isNotice,
    kstDateTime
  ]);
  const postId = result.lastID;
  
  if (req.files && req.files.length > 0) {
    const firstImage = `/public/uploads/${req.files[0].filename}`;
    await db.run('UPDATE golf_posts SET image_path = ? WHERE id = ?', [firstImage, postId]);
    
    for (let i = 0; i < req.files.length; i++) {
      const imagePath = `/public/uploads/${req.files[i].filename}`;
      await db.run(
        'INSERT INTO golf_post_images (post_id, image_path, display_order) VALUES (?, ?, ?)',
        [postId, imagePath, i]
      );
    }
  }
  
  res.redirect('/golf-board.html');
});

// Golf 게시글 상세
app.get('/golf/posts/:id', async (req, res) => {
  const post = await db.get(
    `SELECT p.id, p.title, p.content, p.image_path, p.created_at, p.updated_at, p.is_notice, p.view_count, p.category,
            CASE WHEN u.is_admin = 1 THEN '관리자' ELSE u.username END as username, 
            u.id as user_id
     FROM golf_posts p JOIN golf_users u ON u.id = p.user_id
     WHERE p.id = ?`,
    [req.params.id]
  );
  
  if (!post) return res.status(404).send('Not Found');
  
  await db.run('UPDATE golf_posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?', [req.params.id]);
  
  let images = await db.all(
    'SELECT id, image_path, display_order FROM golf_post_images WHERE post_id = ? ORDER BY display_order ASC',
    [req.params.id]
  );
  
  if (images.length === 0 && post.image_path) {
    images = [{ id: null, image_path: post.image_path, display_order: 0 }];
  }
  
  const categoryName = post.category === 'free' ? '자유게시판' : (post.category === 'general' ? '알림게시판' : '게시판');
  
  res.render('board/detail', { 
    post, 
    images: images || [], 
    category: post.category,
    categoryName: categoryName,
    categoryRoute: '/golf-board.html',
    orgType: 'golf',
    orgName: '한국장애인스크린파크골프협회'
  });
});

// Home redirect helper (선택)
app.get('/', (req, res) => res.redirect('/home'));
app.get('/home', (req, res) => {
  const homePath = path.join(ROOT_STATIC, 'index.html');
  if (fs.existsSync(homePath)) {
    return res.sendFile(homePath);
  }
  return res.redirect('/board');
});

const PORT = process.env.PORT || 5000;
// 전역 에러 핸들러
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR]', err);
  console.error('[GLOBAL ERROR] Stack:', err.stack);
  if (req.headers['content-type']?.includes('application/json')) {
    return res.status(500).json({ 
      error: '서버 오류가 발생했습니다.',
      details: process.env.NODE_ENV === 'production' ? undefined : err.message 
    });
  }
  res.status(500).send('서버 오류가 발생했습니다.');
});

// 데이터베이스 초기화 및 서버 시작
initDb()
  .then(() => {
    console.log('Database initialized successfully');
    app.listen(PORT, () => console.log(`Server running on ${PORT}`));
  })
  .catch((error) => {
    console.error('[INIT ERROR] Failed to initialize database:', error);
    console.error('[INIT ERROR] Stack:', error.stack);
    process.exit(1);
  });
