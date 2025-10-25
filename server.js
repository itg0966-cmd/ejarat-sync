// server.js
// خادم مزامنة مبسّط للفواتير — متوافق مع الواجهة الحالية

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// ===== الوسطاء =====
app.use(cors()); // كل الأصول مسموحة
app.use(express.json({ limit: "5mb" })); // JSON body

// ===== اتصال MongoDB =====
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI مفقود في متغيرات البيئة");
  process.exit(1);
}

await mongoose.connect(MONGO_URI, {
  // منذ Mongoose 8 الخيارات الافتراضية جيدة
  dbName: "ejarat_sync",
});
console.log("✅ تم الاتصال بـ MongoDB");

// ===== النماذج =====
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, default: "" },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const snapshotSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, required: true },
    data: { type: Object, default: {} }, // نخزن الـ DB كاملاً ككائن
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Snapshot = mongoose.model("Snapshot", snapshotSchema);

// ===== JWT =====
const JWT_SECRET = process.env.JWT_SECRET || "change_me_now";
function signToken(user) {
  // نضع المعرف في الـ sub
  return jwt.sign({ sub: user._id.toString(), email: user.email, name: user.name }, JWT_SECRET, {
    expiresIn: "30d",
  });
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: "مطلوب توكن" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { sub, email, name, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: "توكن غير صالح" });
  }
}

// ===== مسارات عامة =====
app.get("/", (req, res) => {
  res.json({ ok: true, msg: "ejarat-sync API شغّال" });
});

app.get("/healthz", (req, res) => {
  res.json({ ok: true, msg: "Server working fine ✅" });
});

// ===== التسجيل والدخول =====
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "أدخل الإيميل وكلمة السر" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ error: "المستخدم موجود مسبقاً" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email: email.toLowerCase(), name: name || "", passwordHash });

    const token = signToken(user);
    res.status(201).json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "فشل التسجيل" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "أدخل الإيميل وكلمة السر" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: "بيانات غير صحيحة" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "بيانات غير صحيحة" });

    const token = signToken(user);
    res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تسجيل الدخول" });
  }
});

// ===== المزامنة =====
// push: يستقبل { data: <DB كامل> } ويخزنه للمستخدم
app.post("/data/push", auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const payload = req.body || {};
    if (!payload || typeof payload !== "object") {
      return res.status(400).json({ error: "بيانات غير صالحة" });
    }

    const snap = await Snapshot.findOneAndUpdate(
      { userId },
      { $set: { data: payload.data || {} } },
      { new: true, upsert: true }
    );

    res.json({ ok: true, updatedAt: snap.updatedAt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "فشل حفظ البيانات" });
  }
});

// pull: يعيد آخر نسخة محفوظة
app.get("/data/pull", auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const snap = await Snapshot.findOne({ userId });
    res.json({ ok: true, data: snap ? snap.data : null, updatedAt: snap ? snap.updatedAt : null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "فشل جلب البيانات" });
  }
});

// ===== تشغيل الخادم =====
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("✅ Server running on port", PORT);
});
