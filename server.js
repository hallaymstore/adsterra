require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/adsterra_reward_project';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const COOKIE_NAME = process.env.COOKIE_NAME || 'reward_token';
const WITHDRAW_MIN = Number(process.env.WITHDRAW_MIN || 0.5);
const ESTIMATED_PROVIDER_CPM_USD = Number(process.env.ESTIMATED_PROVIDER_CPM_USD || 1.6);
const VIEW_SECONDS = Number(process.env.VIEW_SECONDS || 5);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 2 * 60 * 1000);
const AD_COOLDOWN_MS = Number(process.env.AD_COOLDOWN_MS || 7000);
const AUTOWATCH_PRICE_USD = Number(process.env.AUTOWATCH_PRICE_USD || 0.49);
const AUTOWATCH_CAP_USD = Number(process.env.AUTOWATCH_CAP_USD || 1.51);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
}));

mongoose.set('strictQuery', true);

const userSchema = new mongoose.Schema({
  firstName: { type: String, trim: true, maxlength: 60 },
  lastName: { type: String, trim: true, maxlength: 60 },
  fullName: { type: String, trim: true, maxlength: 130 },
  email: { type: String, unique: true, required: true, lowercase: true, trim: true, index: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
  status: { type: String, enum: ['active', 'blocked'], default: 'active', index: true },
  balance: { type: Number, default: 0 },
  frozenBalance: { type: Number, default: 0 },
  totalEarned: { type: Number, default: 0 },
  totalWithdrawn: { type: Number, default: 0 },
  adViews: { type: Number, default: 0 },
  luckyRewards: { type: Number, default: 0 },
  autoWatchActive: { type: Boolean, default: false, index: true },
  autoWatchEarned: { type: Number, default: 0 },
  autoWatchCap: { type: Number, default: 0 },
  autoWatchPricePaid: { type: Number, default: 0 },
  autoWatchPassesPurchased: { type: Number, default: 0 },
  autoWatchStartedAt: { type: Date, default: null },
  autoWatchCompletedAt: { type: Date, default: null },
  autoWatchLastPurchasedAt: { type: Date, default: null },
  referralCode: { type: String, unique: true, sparse: true, index: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  lastAdStartedAt: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null }
}, { timestamps: true });

const adSessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sessionId: { type: String, unique: true, required: true, index: true },
  status: { type: String, enum: ['started', 'completed', 'expired'], default: 'started', index: true },
  reward: { type: Number, default: 0 },
  viewNo: { type: Number, default: 0 },
  isLucky: { type: Boolean, default: false },
  mode: { type: String, enum: ['manual', 'smart'], default: 'manual', index: true },
  ip: String,
  userAgent: String,
  startedAt: { type: Date, default: Date.now, index: true },
  completedAt: Date
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['ad_reward', 'withdraw_request', 'withdraw_approved', 'withdraw_rejected', 'admin_adjust', 'autowatch_purchase'], required: true, index: true },
  amount: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  note: { type: String, maxlength: 500 },
  meta: { type: Object, default: {} }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  payeerAccount: { type: String, trim: true, required: true, maxlength: 80 },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
  adminNote: { type: String, trim: true, maxlength: 500 },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  processedAt: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const AdSession = mongoose.model('AdSession', adSessionSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

function cleanString(value, max = 200) {
  return String(value || '').replace(/[<>]/g, '').trim().slice(0, max);
}

function emailOk(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function money(n, digits = 6) {
  return Number(Number(n || 0).toFixed(digits));
}

function makeReferralCode() {
  return crypto.randomBytes(5).toString('hex').toUpperCase();
}

function signToken(user) {
  return jwt.sign({ id: String(user._id), role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

async function authRequired(req, res, next) {
  try {
    const raw = req.cookies[COOKIE_NAME] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!raw) return res.status(401).json({ ok: false, message: 'Login required' });
    const payload = jwt.verify(raw, JWT_SECRET);
    const user = await User.findById(payload.id).select('-passwordHash');
    if (!user) return res.status(401).json({ ok: false, message: 'User not found' });
    if (user.status !== 'active') return res.status(403).json({ ok: false, message: 'Account blocked' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, message: 'Invalid session' });
  }
}

function adminRequired(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ ok: false, message: 'Admin only' });
  }
  next();
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
}

function calculateReward(nextViewNo) {
  // Ichki ledger modeli: uzoq muddatda taxminan $1 / 1200 view atrofida ushlab turiladi.
  // Dastlab onboarding reward kattaroq, keyin kamayadi. Random lucky bonuslar ham bor.
  let min;
  let max;

  if (nextViewNo <= 5) {
    min = 0.006;
    max = 0.010;
  } else if (nextViewNo <= 25) {
    min = 0.0015;
    max = 0.0035;
  } else if (nextViewNo <= 120) {
    min = 0.00075;
    max = 0.0014;
  } else if (nextViewNo <= 600) {
    min = 0.00055;
    max = 0.00095;
  } else {
    min = 0.00038;
    max = 0.00082;
  }

  let reward = min + Math.random() * (max - min);
  let isLucky = false;

  const luckyChance = nextViewNo <= 30 ? 0.08 : 0.022;
  if (Math.random() < luckyChance) {
    isLucky = true;
    const luckyBonus = 0.001 + Math.random() * 0.007;
    reward += luckyBonus;
  }

  return { reward: money(reward, 6), isLucky };
}

function publicUser(user) {
  return {
    id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    fullName: user.fullName,
    email: user.email,
    role: user.role,
    status: user.status,
    balance: money(user.balance),
    frozenBalance: money(user.frozenBalance),
    totalEarned: money(user.totalEarned),
    totalWithdrawn: money(user.totalWithdrawn),
    adViews: user.adViews,
    luckyRewards: user.luckyRewards,
    autoWatch: {
      active: Boolean(user.autoWatchActive),
      earned: money(user.autoWatchEarned),
      cap: money(user.autoWatchCap),
      remaining: money(Math.max(0, (user.autoWatchCap || 0) - (user.autoWatchEarned || 0))),
      pricePaid: money(user.autoWatchPricePaid),
      passesPurchased: user.autoWatchPassesPurchased || 0,
      startedAt: user.autoWatchStartedAt,
      completedAt: user.autoWatchCompletedAt,
      lastPurchasedAt: user.autoWatchLastPurchasedAt
    },
    referralCode: user.referralCode,
    createdAt: user.createdAt
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'reward-platform', time: new Date().toISOString() });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const firstName = cleanString(req.body.firstName, 60);
    const lastName = cleanString(req.body.lastName, 60);
    const email = cleanString(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    const ref = cleanString(req.body.ref, 40).toUpperCase();

    if (!firstName || !lastName) return res.status(400).json({ ok: false, message: 'First and last name are required' });
    if (!emailOk(email)) return res.status(400).json({ ok: false, message: 'Invalid email address' });
    if (password.length < 6) return res.status(400).json({ ok: false, message: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ ok: false, message: 'This email is already registered' });

    let referredBy = null;
    if (ref) {
      const refUser = await User.findOne({ referralCode: ref });
      if (refUser) referredBy = refUser._id;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    let referralCode = makeReferralCode();
    while (await User.findOne({ referralCode })) referralCode = makeReferralCode();

    const user = await User.create({
      firstName,
      lastName,
      fullName: `${firstName} ${lastName}`,
      email,
      passwordHash,
      referralCode,
      referredBy,
      lastLoginAt: new Date()
    });

    const token = signToken(user);
    setAuthCookie(res, token);
    return res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = cleanString(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    if (user.status !== 'active') return res.status(403).json({ ok: false, message: 'Account blocked' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    user.lastLoginAt = new Date();
    await user.save();
    const token = signToken(user);
    setAuthCookie(res, token);
    return res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user), config: { withdrawMin: WITHDRAW_MIN, viewSeconds: VIEW_SECONDS, autoWatchPrice: AUTOWATCH_PRICE_USD, autoWatchCap: AUTOWATCH_CAP_USD } });
});


app.post('/api/autowatch/buy', authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });

    const activeRemaining = Boolean(user.autoWatchActive) && Number(user.autoWatchEarned || 0) < Number(user.autoWatchCap || 0);
    if (activeRemaining) {
      return res.status(409).json({ ok: false, message: 'Smart Auto Mode is already active', user: publicUser(user) });
    }

    if (Number(user.balance || 0) < AUTOWATCH_PRICE_USD) {
      return res.status(400).json({ ok: false, message: `Insufficient balance. Smart Auto Mode costs $${AUTOWATCH_PRICE_USD.toFixed(2)}` });
    }

    user.balance = money(user.balance - AUTOWATCH_PRICE_USD);
    user.autoWatchActive = true;
    user.autoWatchEarned = 0;
    user.autoWatchCap = AUTOWATCH_CAP_USD;
    user.autoWatchPricePaid = AUTOWATCH_PRICE_USD;
    user.autoWatchPassesPurchased = Number(user.autoWatchPassesPurchased || 0) + 1;
    user.autoWatchStartedAt = new Date();
    user.autoWatchCompletedAt = null;
    user.autoWatchLastPurchasedAt = new Date();
    await user.save();

    await Transaction.create({
      user: user._id,
      type: 'autowatch_purchase',
      amount: -AUTOWATCH_PRICE_USD,
      balanceAfter: user.balance,
      note: 'Smart Auto Mode pass purchased',
      meta: { price: AUTOWATCH_PRICE_USD, cap: AUTOWATCH_CAP_USD }
    });

    res.json({ ok: true, user: publicUser(user), config: { autoWatchPrice: AUTOWATCH_PRICE_USD, autoWatchCap: AUTOWATCH_CAP_USD } });
  } catch (err) {
    console.error('autowatch buy error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.post('/api/ad/session', authRequired, async (req, res) => {
  try {
    const fresh = await User.findById(req.user._id);
    const requestedMode = cleanString(req.body.mode, 20) === 'smart' ? 'smart' : 'manual';

    if (requestedMode === 'smart') {
      const activeRemaining = Boolean(fresh.autoWatchActive) && Number(fresh.autoWatchEarned || 0) < Number(fresh.autoWatchCap || 0);
      if (!activeRemaining) {
        if (fresh.autoWatchActive) {
          fresh.autoWatchActive = false;
          fresh.autoWatchCompletedAt = new Date();
          await fresh.save();
        }
        return res.status(403).json({ ok: false, message: 'Smart Auto Mode is not active. Buy a new pass to continue.' });
      }
    }

    const now = Date.now();
    if (fresh.lastAdStartedAt && now - fresh.lastAdStartedAt.getTime() < AD_COOLDOWN_MS) {
      const waitMs = AD_COOLDOWN_MS - (now - fresh.lastAdStartedAt.getTime());
      return res.status(429).json({ ok: false, message: `Wait ${Math.ceil(waitMs / 1000)} seconds before the next ad`, waitMs });
    }

    fresh.lastAdStartedAt = new Date();
    await fresh.save();

    const sessionId = crypto.randomUUID();
    await AdSession.create({
      user: fresh._id,
      sessionId,
      mode: requestedMode,
      ip: getClientIp(req),
      userAgent: cleanString(req.headers['user-agent'], 300),
      startedAt: new Date()
    });

    res.json({ ok: true, sessionId, mode: requestedMode, viewSeconds: VIEW_SECONDS, user: publicUser(fresh) });
  } catch (err) {
    console.error('ad session error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});


app.post('/api/ad/complete', authRequired, async (req, res) => {
  try {
    const sessionId = cleanString(req.body.sessionId, 100);
    const session = await AdSession.findOne({ sessionId, user: req.user._id });
    if (!session) return res.status(404).json({ ok: false, message: 'Ad session not found' });
    if (session.status === 'completed') return res.status(409).json({ ok: false, message: 'This ad session was already credited' });

    const elapsed = Date.now() - session.startedAt.getTime();
    if (elapsed < VIEW_SECONDS * 1000) {
      return res.status(400).json({ ok: false, message: `Watch for at least ${VIEW_SECONDS} seconds before claiming the reward` });
    }
    if (elapsed > SESSION_TTL_MS) {
      session.status = 'expired';
      await session.save();
      return res.status(400).json({ ok: false, message: 'Session expired, please try again' });
    }

    const user = await User.findById(req.user._id);
    const nextViewNo = user.adViews + 1;
    let { reward, isLucky } = calculateReward(nextViewNo);

    if (session.mode === 'smart') {
      const activeRemaining = Boolean(user.autoWatchActive) && Number(user.autoWatchEarned || 0) < Number(user.autoWatchCap || 0);
      if (!activeRemaining) {
        user.autoWatchActive = false;
        user.autoWatchCompletedAt = new Date();
        await user.save();
        return res.status(403).json({ ok: false, message: 'Smart Auto Mode cap reached. Buy a new pass to continue.', user: publicUser(user) });
      }
      const remaining = money((user.autoWatchCap || 0) - (user.autoWatchEarned || 0), 6);
      reward = money(Math.min(reward, remaining), 6);
      user.autoWatchEarned = money((user.autoWatchEarned || 0) + reward, 6);
      if (user.autoWatchEarned >= user.autoWatchCap - 0.000001) {
        user.autoWatchActive = false;
        user.autoWatchCompletedAt = new Date();
      }
    }

    user.balance = money(user.balance + reward);
    user.totalEarned = money(user.totalEarned + reward);
    user.adViews = nextViewNo;
    if (isLucky) user.luckyRewards += 1;
    await user.save();

    session.status = 'completed';
    session.reward = reward;
    session.viewNo = nextViewNo;
    session.isLucky = isLucky;
    session.completedAt = new Date();
    await session.save();

    await Transaction.create({
      user: user._id,
      type: 'ad_reward',
      amount: reward,
      balanceAfter: user.balance,
      note: session.mode === 'smart' ? (isLucky ? 'Smart Auto Mode lucky reward' : 'Smart Auto Mode reward') : (isLucky ? 'Lucky ad reward' : 'Ad reward'),
      meta: { sessionId, viewNo: nextViewNo, isLucky, mode: session.mode }
    });

    return res.json({ ok: true, reward, isLucky, mode: session.mode, autoWatchCompleted: session.mode === 'smart' && !user.autoWatchActive, user: publicUser(user) });
  } catch (err) {
    console.error('ad complete error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.get('/api/transactions', authRequired, async (req, res) => {
  const rows = await Transaction.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(60).lean();
  res.json({ ok: true, transactions: rows });
});

app.get('/api/withdrawals', authRequired, async (req, res) => {
  const rows = await Withdrawal.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(60).lean();
  res.json({ ok: true, withdrawals: rows, withdrawMin: WITHDRAW_MIN });
});

app.post('/api/withdrawals', authRequired, async (req, res) => {
  try {
    const payeerAccount = cleanString(req.body.payeerAccount, 80);
    const amount = money(req.body.amount, 6);
    if (!payeerAccount || payeerAccount.length < 5) return res.status(400).json({ ok: false, message: 'Enter a valid Payeer account' });
    if (!Number.isFinite(amount) || amount < WITHDRAW_MIN) return res.status(400).json({ ok: false, message: `Minimum withdrawal amount is $${WITHDRAW_MIN}` });

    const user = await User.findById(req.user._id);
    if (user.balance < amount) return res.status(400).json({ ok: false, message: 'Insufficient balance' });

    user.balance = money(user.balance - amount);
    user.frozenBalance = money(user.frozenBalance + amount);
    await user.save();

    const withdrawal = await Withdrawal.create({ user: user._id, payeerAccount, amount });
    await Transaction.create({
      user: user._id,
      type: 'withdraw_request',
      amount: -amount,
      balanceAfter: user.balance,
      note: 'Withdrawal request created',
      meta: { withdrawalId: withdrawal._id, payeerAccount }
    });

    res.json({ ok: true, withdrawal, user: publicUser(user) });
  } catch (err) {
    console.error('withdrawal create error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.get('/api/admin/stats', authRequired, adminRequired, async (req, res) => {
  const [totalUsers, activeUsers, blockedUsers, autoWatchUsers, adStats, balanceStats, autoWatchStats, pendingWithdrawals, approvedWithdrawals, rejectedWithdrawals] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ status: 'active' }),
    User.countDocuments({ status: 'blocked' }),
    User.countDocuments({ autoWatchActive: true }),
    User.aggregate([{ $group: { _id: null, totalViews: { $sum: '$adViews' }, totalEarned: { $sum: '$totalEarned' }, totalWithdrawn: { $sum: '$totalWithdrawn' }, luckyRewards: { $sum: '$luckyRewards' } } }]),
    User.aggregate([{ $group: { _id: null, totalBalance: { $sum: '$balance' }, totalFrozen: { $sum: '$frozenBalance' } } }]),
    Transaction.aggregate([{ $match: { type: 'autowatch_purchase' } }, { $group: { _id: null, count: { $sum: 1 }, amount: { $sum: '$amount' } } }]),
    Withdrawal.aggregate([{ $match: { status: 'pending' } }, { $group: { _id: null, count: { $sum: 1 }, amount: { $sum: '$amount' } } }]),
    Withdrawal.aggregate([{ $match: { status: 'approved' } }, { $group: { _id: null, count: { $sum: 1 }, amount: { $sum: '$amount' } } }]),
    Withdrawal.aggregate([{ $match: { status: 'rejected' } }, { $group: { _id: null, count: { $sum: 1 }, amount: { $sum: '$amount' } } }])
  ]);

  const a = adStats[0] || { totalViews: 0, totalEarned: 0, totalWithdrawn: 0, luckyRewards: 0 };
  const b = balanceStats[0] || { totalBalance: 0, totalFrozen: 0 };
  const aw = autoWatchStats[0] || { count: 0, amount: 0 };
  const p = pendingWithdrawals[0] || { count: 0, amount: 0 };
  const ap = approvedWithdrawals[0] || { count: 0, amount: 0 };
  const rj = rejectedWithdrawals[0] || { count: 0, amount: 0 };
  const estimatedProviderRevenue = money((a.totalViews / 1000) * ESTIMATED_PROVIDER_CPM_USD, 4);
  const estimatedPlatformGross = money(estimatedProviderRevenue - a.totalEarned, 4);

  res.json({
    ok: true,
    stats: {
      totalUsers,
      activeUsers,
      blockedUsers,
      autoWatchUsers,
      autoWatchPurchases: { count: aw.count, amount: money(Math.abs(aw.amount || 0)) },
      totalViews: a.totalViews,
      luckyRewards: a.luckyRewards,
      totalUserRewards: money(a.totalEarned),
      totalBalance: money(b.totalBalance),
      totalFrozen: money(b.totalFrozen),
      totalWithdrawn: money(a.totalWithdrawn),
      pendingWithdrawals: { count: p.count, amount: money(p.amount) },
      approvedWithdrawals: { count: ap.count, amount: money(ap.amount) },
      rejectedWithdrawals: { count: rj.count, amount: money(rj.amount) },
      estimatedProviderCpmUsd: ESTIMATED_PROVIDER_CPM_USD,
      estimatedProviderRevenue,
      estimatedPlatformGross
    }
  });
});

app.get('/api/admin/users', authRequired, adminRequired, async (req, res) => {
  const q = cleanString(req.query.q, 120);
  const filter = q ? { $or: [{ email: new RegExp(q, 'i') }, { fullName: new RegExp(q, 'i') }, { referralCode: new RegExp(q, 'i') }] } : {};
  const users = await User.find(filter).select('-passwordHash').sort({ createdAt: -1 }).limit(250).lean();
  res.json({ ok: true, users });
});

app.patch('/api/admin/users/:id', authRequired, adminRequired, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });

    const allowedStatus = ['active', 'blocked'];
    const allowedRole = ['user', 'admin'];

    if (req.body.firstName !== undefined) user.firstName = cleanString(req.body.firstName, 60);
    if (req.body.lastName !== undefined) user.lastName = cleanString(req.body.lastName, 60);
    if (req.body.firstName !== undefined || req.body.lastName !== undefined) user.fullName = `${user.firstName} ${user.lastName}`.trim();
    if (req.body.status !== undefined && allowedStatus.includes(req.body.status)) user.status = req.body.status;
    if (req.body.role !== undefined && allowedRole.includes(req.body.role)) user.role = req.body.role;
    if (req.body.balance !== undefined) user.balance = Math.max(0, money(req.body.balance, 6));

    await user.save();
    await Transaction.create({
      user: user._id,
      type: 'admin_adjust',
      amount: 0,
      balanceAfter: user.balance,
      note: `Admin edit by ${req.user.email}`,
      meta: { adminId: req.user._id }
    });
    res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('admin user patch error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.get('/api/admin/withdrawals', authRequired, adminRequired, async (req, res) => {
  const status = cleanString(req.query.status, 20);
  const filter = status && ['pending', 'approved', 'rejected'].includes(status) ? { status } : {};
  const withdrawals = await Withdrawal.find(filter).populate('user', 'fullName email balance frozenBalance adViews totalEarned').sort({ createdAt: -1 }).limit(250).lean();
  res.json({ ok: true, withdrawals });
});

app.patch('/api/admin/withdrawals/:id', authRequired, adminRequired, async (req, res) => {
  try {
    const action = cleanString(req.body.action, 20);
    const adminNote = cleanString(req.body.adminNote, 500);
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ ok: false, message: 'Invalid action' });

    const withdrawal = await Withdrawal.findById(req.params.id);
    if (!withdrawal) return res.status(404).json({ ok: false, message: 'Request not found' });
    if (withdrawal.status !== 'pending') return res.status(409).json({ ok: false, message: 'This request has already been processed' });

    const user = await User.findById(withdrawal.user);
    if (!user) return res.status(404).json({ ok: false, message: 'User not found' });

    if (action === 'approve') {
      if (user.frozenBalance < withdrawal.amount) return res.status(400).json({ ok: false, message: 'Frozen balance is not enough' });
      user.frozenBalance = money(user.frozenBalance - withdrawal.amount);
      user.totalWithdrawn = money(user.totalWithdrawn + withdrawal.amount);
      withdrawal.status = 'approved';
      await Transaction.create({
        user: user._id,
        type: 'withdraw_approved',
        amount: -withdrawal.amount,
        balanceAfter: user.balance,
        note: adminNote || 'Withdrawal approved',
        meta: { withdrawalId: withdrawal._id, adminId: req.user._id }
      });
    } else {
      user.frozenBalance = money(Math.max(0, user.frozenBalance - withdrawal.amount));
      user.balance = money(user.balance + withdrawal.amount);
      withdrawal.status = 'rejected';
      await Transaction.create({
        user: user._id,
        type: 'withdraw_rejected',
        amount: withdrawal.amount,
        balanceAfter: user.balance,
        note: adminNote || 'Withdrawal rejected and funds returned',
        meta: { withdrawalId: withdrawal._id, adminId: req.user._id }
      });
    }

    withdrawal.adminNote = adminNote;
    withdrawal.processedBy = req.user._id;
    withdrawal.processedAt = new Date();
    await user.save();
    await withdrawal.save();

    res.json({ ok: true, withdrawal, user: publicUser(user) });
  } catch (err) {
    console.error('withdrawal admin patch error', err);
    res.status(500).json({ ok: false, message: 'Server error' });
  }
});

app.get('/api/admin/recent-ad-sessions', authRequired, adminRequired, async (req, res) => {
  const sessions = await AdSession.find({ status: 'completed' }).populate('user', 'fullName email').sort({ completedAt: -1 }).limit(100).lean();
  res.json({ ok: true, sessions });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/withdraw', (req, res) => res.sendFile(path.join(__dirname, 'public', 'withdraw.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
  const password = process.env.ADMIN_PASSWORD || 'admin12345';
  const exists = await User.findOne({ email });
  if (exists) {
    if (exists.role !== 'admin') {
      exists.role = 'admin';
      await exists.save();
    }
    return;
  }
  const passwordHash = await bcrypt.hash(password, 12);
  let referralCode = makeReferralCode();
  while (await User.findOne({ referralCode })) referralCode = makeReferralCode();
  await User.create({
    firstName: 'Admin',
    lastName: 'User',
    fullName: 'Admin User',
    email,
    passwordHash,
    role: 'admin',
    referralCode
  });
  console.log(`Admin seeded: ${email} / ${password}`);
}

async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    await seedAdmin();
    app.listen(PORT, () => {
      console.log(`Reward platform running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Startup failed', err);
    process.exit(1);
  }
}

start();
