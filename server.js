// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// ---------- Middlewares ----------
app.use(cors());                 // افتحها للكل. تقدر تحدد origin لاحقًا
app.use(express.json({ limit: "1mb" })); // JSON body

// ---------- اتصال MongoDB ----------
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI مفقود في .env");
  process.exit(1);
}

await mongoose.connect(MONGO_URI, {
  // مع Mongoose 8 ما تحتاج useNewUrlParser/useUnifiedTopology
  dbName: "ejarat_sync",
});
console.log("✅ تم الاتصال بقاعدة MongoDB Atlas");

// ---------- نماذج (Schemas) ----------
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, default: "" },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const invoiceSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    title: String,
    amount: Number,
    month: String,   // مثال: "2025-10"
    notes: String,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Invoice = mongoose.model("Invoice", invoiceSchema);

// ---------- أدوات JWT ----------
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const signToken = (user) =>
  jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, {
    expiresIn: "30d",
  });

const auth = (req, res, next) => {
  // توقع Authorization: Bearer <token>
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: "مطلوب تسجيل الدخول" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "جلسة غير صالحة" });
  }
};

// ---------- Routes بسيطة ----------
app.get("/", (_req, res) => {
  res.json({ ok: true, msg: "ejarat-sync API شغال" });
});

// تسجيل مستخدم جديد
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, name = "" } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "أدخل البريد وكلمة المرور" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ error: "البريد مسجل من قبل" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, name, passwordHash });
    const token = signToken(user);

    res.status(201).json({
      token,
      user: { id: user._id, email: user.email, name: user.name },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في السيرفر" });
  }
});

// تسجيل الدخول
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "أدخل البريد وكلمة المرور" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: "بيانات غير صحيحة" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "بيانات غير صحيحة" });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في السيرفر" });
  }
});

// معلومات المستخدم الحالي
app.get("/api/me", auth, async (req, res) => {
  const user = await User.findById(req.user.sub).select("_id email name createdAt updatedAt");
  res.json({ user });
});

// أمثلة فواتير مرتبطة بالمستخدم
app.get("/api/invoices", auth, async (req, res) => {
  const items = await Invoice.find({ userId: req.user.sub }).sort({ createdAt: -1 });
  res.json({ items });
});

app.post("/api/invoices", auth, async (req, res) => {
  const { title, amount, month, notes } = req.body || {};
  const inv = await Invoice.create({ userId: req.user.sub, title, amount, month, notes });
  res.status(201).json({ item: inv });
});

app.delete("/api/invoices/:id", auth, async (req, res) => {
  const { id } = req.params;
  await Invoice.deleteOne({ _id: id, userId: req.user.sub });
  res.json({ ok: true });
});

// ---------- تشغيل ----------
const PORT = Number(process.env.PORT || 8080);
app.listen(PORT, () => {
  console.log(`✅ السيرفر شغال على http://localhost:${PORT}`);
});
