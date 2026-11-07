import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createHash, randomUUID } from "node:crypto";
import type { RowDataPacket, ResultSetHeader } from "mysql2";
import { db } from "./db.js";
import { prisma } from "./prisma.js";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET: string = process.env.JWT_SECRET ?? "";

if (JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET wajib diisi dengan secret minimal 32 karakter.");
}

const TOKEN_TTL_SECONDS = 2 * 60 * 60;

app.use(cors());
app.use(express.json());

type AdminRow = RowDataPacket & {
  id: number;
  name: string;
  email: string;
  password: string;
  role: "admin" | "user";
  status: "active" | "inactive" | "blocked";
};

type SessionRow = RowDataPacket & {
  id: number;
};

type ManagedUserRow = RowDataPacket & {
  id: number;
  name: string;
  email: string;
  role: "admin" | "user";
  status: "active" | "inactive" | "blocked";
  created_at: Date;
  updated_at: Date;
};

type CountRow = RowDataPacket & {
  total: number;
};

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// Middleware autentikasi token dan validasi admin aktif
async function authenticateToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const authorization = req.headers.authorization;
  const [scheme, token] = authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      message: "Token autentikasi diperlukan.",
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    }) as jwt.JwtPayload;

    if (
      typeof payload.sub !== "string" ||
      typeof payload.jti !== "string"
    ) {
      return res.status(401).json({
        message: "Token tidak valid.",
      });
    }

    const adminId = Number(payload.sub);

    if (!Number.isSafeInteger(adminId) || adminId <= 0) {
      return res.status(401).json({
        message: "Token tidak valid.",
      });
    }

    const [sessions] = await db.execute<SessionRow[]>(
      `SELECT id
       FROM admin_sessions
       WHERE user_id = ?
         AND token_hash = ?
         AND expires_at > UTC_TIMESTAMP()
       LIMIT 1`,
      [adminId, hashToken(token)],
    );

    if (sessions.length === 0) {
      return res.status(401).json({
        message: "Token sudah tidak berlaku. Silakan login kembali.",
      });
    }

    const admin = await prisma.users.findUnique({
      where: { id: adminId },
      select: {
        id: true,
        role: true,
        status: true,
      },
    });

    if (
      !admin ||
      admin.role !== "admin" ||
      admin.status !== "active"
    ) {
      return res.status(403).json({
        message: "Akun tidak memiliki akses admin aktif.",
      });
    }

    res.locals.adminId = adminId;
    res.locals.token = token;

    return next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({
        message: "Token tidak valid atau sudah kedaluwarsa.",
      });
    }

    console.error("Validasi token gagal:", error);
    return res.status(500).json({
      message: "Terjadi kesalahan pada server.",
    });
  }
}

// Cek backend
app.get("/", (_req, res) => {
  res.json({
    message: "Backend Agro Wisata Petik Jeruk berhasil berjalan!",
  });
});

// Cek koneksi MySQL
app.get("/api/db-test", async (_req, res) => {
  try {
    const [rows] = await db.query("SELECT 1 AS connected");

    return res.json({
      message: "Koneksi MySQL berhasil!",
      data: rows,
    });
  } catch (error) {
    console.error("Koneksi MySQL gagal:", error);
    return res.status(500).json({
      message: "Koneksi MySQL gagal",
    });
  }
});

// Login admin dan buat Bearer Token
app.post("/api/admin/login", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");

  if (!email || !password) {
    return res.status(400).json({
      message: "Email dan password wajib diisi.",
    });
  }

  try {
    const [rows] = await db.execute<AdminRow[]>(
      `SELECT id, name, email, password, role, status
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email],
    );

    const admin = rows[0];

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({
        message: "Email atau password salah.",
      });
    }

    if (admin.role !== "admin" || admin.status !== "active") {
      return res.status(403).json({
        message: "Akun tidak memiliki akses admin aktif.",
      });
    }

    const jti = randomUUID();

    const token = jwt.sign(
      { jti },
      JWT_SECRET,
      {
        algorithm: "HS256",
        subject: String(admin.id),
        expiresIn: TOKEN_TTL_SECONDS,
      },
    );

    const expiresAt = new Date(Date.now() + TOKEN_TTL_SECONDS * 1000);

    await db.execute(
      `INSERT INTO admin_sessions (user_id, token_hash, expires_at)
       VALUES (?, ?, ?)`,
      [admin.id, hashToken(token), expiresAt],
    );

    return res.json({
      message: "Login berhasil.",
      token_type: "Bearer",
      access_token: token,
      expires_in: TOKEN_TTL_SECONDS,
      user: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error("Login admin gagal:", error);
    return res.status(500).json({
      message: "Terjadi kesalahan pada server.",
    });
  }
});

// Periksa token yang sedang digunakan + ambil profil admin
app.get("/api/admin/me", authenticateToken, async (_req, res) => {
  try {
    const admin = await prisma.users.findUnique({
      where: { id: res.locals.adminId as number },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        status: true,
      },
    });

    if (!admin) {
      return res.status(404).json({
        message: "Pengguna tidak ditemukan.",
      });
    }

    return res.json({
      message: "Token valid.",
      authenticated: true,
      user: admin,
    });
  } catch (error) {
    console.error("Gagal mengambil profil admin:", error);

    return res.status(500).json({
      message: "Terjadi kesalahan pada server.",
    });
  }
});

// Statistik dashboard admin menggunakan Prisma
app.get("/api/admin/dashboard", authenticateToken, async (_req, res) => {
  try {
    const [
      totalUsers,
      totalPackages,
      totalBookings,
      pendingBookings,
      confirmedBookings,
      cancelledBookings,
      totalPayments,
      pendingPayments,
      verifiedPayments,
      rejectedPayments,
      verifiedRevenue,
    ] = await Promise.all([
      prisma.users.count({
        where: { role: "user" },
      }),
      prisma.packages.count(),
      prisma.bookings.count(),
      prisma.bookings.count({
        where: { status: "pending" },
      }),
      prisma.bookings.count({
        where: { status: "confirmed" },
      }),
      prisma.bookings.count({
        where: { status: "cancelled" },
      }),
      prisma.payments.count(),
      prisma.payments.count({
        where: { status: "pending" },
      }),
      prisma.payments.count({
        where: { status: "verified" },
      }),
      prisma.payments.count({
        where: { status: "rejected" },
      }),
      prisma.payments.aggregate({
        where: { status: "verified" },
        _sum: { amount: true },
      }),
    ]);

    const [recentTransactions] = await db.execute<RowDataPacket[]>(
      `SELECT
         b.booking_code,
         b.package_name,
         b.visit_date,
         b.total_amount,
         b.status AS booking_status,
         p.status AS payment_status,
         u.name AS customer_name
       FROM bookings b
       LEFT JOIN payments p ON p.booking_id = b.id
       INNER JOIN users u ON u.id = b.user_id
       ORDER BY b.created_at DESC, b.id DESC
       LIMIT 5`,
    );

    const [monthlyRevenue] = await db.execute<RowDataPacket[]>(
      `SELECT
         DATE_FORMAT(p.created_at, '%Y-%m') AS month,
         COALESCE(SUM(p.amount), 0) AS total
       FROM payments p
       WHERE p.status = 'verified'
         AND p.created_at >= DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 5 MONTH)
       GROUP BY month
       ORDER BY month`,
    );

    return res.json({
      message: "Statistik dashboard berhasil diambil.",
      data: {
        totalUsers,
        totalPackages,
        totalBookings,
        bookings: {
          pending: pendingBookings,
          confirmed: confirmedBookings,
          cancelled: cancelledBookings,
        },
        totalPayments,
        payments: {
          pending: pendingPayments,
          verified: verifiedPayments,
          rejected: rejectedPayments,
        },
        verifiedRevenue: verifiedRevenue._sum.amount?.toString() ?? "0",
        recentTransactions,
        monthlyRevenue,
      },
    });
  } catch (error) {
    console.error("Gagal mengambil statistik dashboard:", error);

    return res.status(500).json({
      message: "Gagal mengambil statistik dashboard.",
    });
  }
});

// Riwayat aktivitas sesi admin terbaru
app.get("/api/admin/login-activity", authenticateToken, async (_req, res) => {
  try {
    const [sessions] = await db.execute<RowDataPacket[]>(
      `SELECT
         s.created_at,
         u.email
       FROM admin_sessions s
       INNER JOIN users u ON u.id = s.user_id
       ORDER BY s.created_at DESC, s.id DESC
       LIMIT 5`,
    );

    return res.json({
      message: "Riwayat aktivitas login berhasil diambil.",
      data: sessions,
    });
  } catch (error) {
    console.error("Gagal mengambil aktivitas login:", error);

    return res.status(500).json({
      message: "Gagal mengambil aktivitas login.",
    });
  }
});

type AdminPaymentRow = RowDataPacket & {
  id: number;
  booking_id: number;
  payment_method: string;
  amount: number;
  proof_path: string | null;
  status: "pending" | "verified" | "rejected";
  verified_by: number | null;
  verified_at: Date | null;
  rejection_reason: string | null;
  created_at: Date;
  booking_code: string;
  package_name: string;
  visit_date: Date;
  visitor_count: number;
  customer_name: string;
  customer_email: string;
};

// GET: Daftar pembayaran untuk admin
app.get("/api/admin/payments", authenticateToken, async (req, res) => {
  try {
    const requestedStatus =
      typeof req.query.status === "string"
        ? req.query.status
        : undefined;

    const allowedStatuses = ["pending", "verified", "rejected"];

    if (
      requestedStatus &&
      !allowedStatuses.includes(requestedStatus)
    ) {
      return res.status(400).json({
        message: "Filter status pembayaran tidak valid.",
      });
    }

    let sql = `
      SELECT
        p.id,
        p.booking_id,
        p.payment_method,
        p.amount,
        p.proof_path,
        p.status,
        p.verified_by,
        p.verified_at,
        p.rejection_reason,
        p.created_at,
        b.booking_code,
        b.package_name,
        b.visit_date,
        b.visitor_count,
        u.name AS customer_name,
        u.email AS customer_email
      FROM payments p
      INNER JOIN bookings b ON b.id = p.booking_id
      INNER JOIN users u ON u.id = b.user_id
    `;

    const params: string[] = [];

    if (requestedStatus) {
      sql += " WHERE p.status = ?";
      params.push(requestedStatus);
    }

    sql += " ORDER BY p.created_at DESC";

    const [payments] = await db.execute<AdminPaymentRow[]>(
      sql,
      params
    );

    return res.json({
      message: "Daftar pembayaran berhasil diambil.",
      total: payments.length,
      data: payments,
    });
  } catch (error) {
    console.error("Gagal mengambil daftar pembayaran:", error);

    return res.status(500).json({
      message: "Terjadi kesalahan saat mengambil daftar pembayaran.",
    });
  }
});

app.patch(
  "/api/admin/payments/:id/verify",
  authenticateToken,
  async (req, res) => {
    const paymentId = Number(req.params.id);

    if (!Number.isSafeInteger(paymentId) || paymentId <= 0) {
      return res.status(400).json({
        message: "ID pembayaran tidak valid.",
      });
    }

    let connection;

    try {
      connection = await db.getConnection();
      await connection.beginTransaction();

      const [rows] = await connection.execute<AdminPaymentRow[]>(
        `SELECT id, booking_id, status
         FROM payments
         WHERE id = ?
         FOR UPDATE`,
        [paymentId]
      );

      const payment = rows[0];

      if (!payment) {
        await connection.rollback();

        return res.status(404).json({
          message: "Pembayaran tidak ditemukan.",
        });
      }

      if (payment.status !== "pending") {
        await connection.rollback();

        return res.status(409).json({
          message: "Pembayaran sudah diproses sebelumnya.",
          status: payment.status,
        });
      }

      await connection.execute(
        `UPDATE payments
         SET status = 'verified',
             verified_by = ?,
             verified_at = NOW(),
             rejection_reason = NULL,
             updated_at = NOW()
         WHERE id = ?`,
        [res.locals.adminId, paymentId]
      );

      await connection.execute(
        `UPDATE bookings
         SET status = 'confirmed',
             updated_at = NOW()
         WHERE id = ?`,
        [payment.booking_id]
      );

      await connection.commit();

      return res.json({
        message: "Pembayaran berhasil diverifikasi.",
        payment_id: paymentId,
        booking_id: payment.booking_id,
        status: "verified",
        booking_status: "confirmed",
      });
    } catch (error) {
      if (connection) {
        await connection.rollback();
      }

      console.error("Gagal memverifikasi pembayaran:", error);

      return res.status(500).json({
        message: "Terjadi kesalahan saat memverifikasi pembayaran.",
      });
    } finally {
      connection?.release();
    }
  }
);

app.patch(
  "/api/admin/payments/:id/reject",
  authenticateToken,
  async (req, res) => {
    const paymentId = Number(req.params.id);
    const reason =
      typeof req.body?.reason === "string"
        ? req.body.reason.trim()
        : "";

    if (!Number.isSafeInteger(paymentId) || paymentId <= 0) {
      return res.status(400).json({
        message: "ID pembayaran tidak valid.",
      });
    }

    if (!reason || reason.length > 500) {
      return res.status(400).json({
        message: "Alasan penolakan wajib diisi, maksimal 500 karakter.",
      });
    }

    let connection;

    try {
      connection = await db.getConnection();
      await connection.beginTransaction();

      const [rows] = await connection.execute<AdminPaymentRow[]>(
        `SELECT id, status
         FROM payments
         WHERE id = ?
         FOR UPDATE`,
        [paymentId]
      );

      const payment = rows[0];

      if (!payment) {
        await connection.rollback();

        return res.status(404).json({
          message: "Pembayaran tidak ditemukan.",
        });
      }

      if (payment.status !== "pending") {
        await connection.rollback();

        return res.status(409).json({
          message: "Pembayaran sudah diproses sebelumnya.",
          status: payment.status,
        });
      }

      await connection.execute(
        `UPDATE payments
         SET status = 'rejected',
             verified_by = ?,
             verified_at = NOW(),
             rejection_reason = ?,
             updated_at = NOW()
         WHERE id = ?`,
        [res.locals.adminId, reason, paymentId]
      );

      await connection.commit();

      return res.json({
        message: "Pembayaran berhasil ditolak.",
        payment_id: paymentId,
        status: "rejected",
        rejection_reason: reason,
      });
    } catch (error) {
      if (connection) {
        await connection.rollback();
      }

      console.error("Gagal menolak pembayaran:", error);

      return res.status(500).json({
        message: "Terjadi kesalahan saat menolak pembayaran.",
      });
    } finally {
      connection?.release();
    }
  }
);

// Kembalikan pembayaran yang ditolak ke status menunggu (aksi "Cek Ulang")
app.patch(
  "/api/admin/payments/:id/reopen",
  authenticateToken,
  async (req, res) => {
    const paymentId = Number(req.params.id);

    if (!Number.isSafeInteger(paymentId) || paymentId <= 0) {
      return res.status(400).json({
        message: "ID pembayaran tidak valid.",
      });
    }

    let connection;

    try {
      connection = await db.getConnection();
      await connection.beginTransaction();

      const [rows] = await connection.execute<AdminPaymentRow[]>(
        `SELECT id, booking_id, status
         FROM payments
         WHERE id = ?
         FOR UPDATE`,
        [paymentId],
      );

      const payment = rows[0];

      if (!payment) {
        await connection.rollback();

        return res.status(404).json({
          message: "Pembayaran tidak ditemukan.",
        });
      }

      if (payment.status !== "rejected") {
        await connection.rollback();

        return res.status(409).json({
          message: "Hanya pembayaran ditolak yang bisa diajukan ulang.",
          status: payment.status,
        });
      }

      await connection.execute(
        `UPDATE payments
         SET status = 'pending',
             verified_by = NULL,
             verified_at = NULL,
             rejection_reason = NULL,
             updated_at = NOW()
         WHERE id = ?`,
        [paymentId],
      );

      await connection.execute(
        `UPDATE bookings
         SET status = 'pending',
             updated_at = NOW()
         WHERE id = ?`,
        [payment.booking_id],
      );

      await connection.commit();

      return res.json({
        message: "Pembayaran dikembalikan ke menunggu verifikasi.",
        payment_id: paymentId,
        booking_id: payment.booking_id,
        status: "pending",
        booking_status: "pending",
      });
    } catch (error) {
      if (connection) {
        await connection.rollback();
      }

      console.error("Gagal membuka kembali pembayaran:", error);

      return res.status(500).json({
        message: "Terjadi kesalahan saat memproses pembayaran.",
      });
    } finally {
      connection?.release();
    }
  },
);

type AdminReportTransaction = RowDataPacket & {
  payment_id: number;
  booking_code: string;
  customer_name: string;
  customer_email: string;
  package_name: string;
  visit_date: Date;
  visitor_count: number;
  payment_method: string;
  amount: number;
  payment_status: "pending" | "verified" | "rejected";
  rejection_reason: string | null;
  payment_created_at: Date;
};

app.get("/api/admin/reports", authenticateToken, async (req, res) => {
  try {
    const from =
      typeof req.query.from === "string" ? req.query.from : undefined;

    const to =
      typeof req.query.to === "string" ? req.query.to : undefined;

    const isValidDate = (value: string) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;

      const date = new Date(`${value}T00:00:00.000Z`);

      return (
        !Number.isNaN(date.getTime()) &&
        date.toISOString().slice(0, 10) === value
      );
    };

    if ((from && !isValidDate(from)) || (to && !isValidDate(to))) {
      return res.status(400).json({
        message: "Format tanggal tidak valid. Gunakan YYYY-MM-DD.",
      });
    }

    if (from && to && from > to) {
      return res.status(400).json({
        message: "Tanggal awal tidak boleh melebihi tanggal akhir.",
      });
    }

    const paymentConditions: string[] = [];
    const bookingConditions: string[] = [];
    const paymentParams: string[] = [];
    const bookingParams: string[] = [];

    if (from) {
      paymentConditions.push("p.created_at >= ?");
      paymentParams.push(`${from} 00:00:00`);

      bookingConditions.push("b.created_at >= ?");
      bookingParams.push(`${from} 00:00:00`);
    }

    if (to) {
      paymentConditions.push("p.created_at < DATE_ADD(?, INTERVAL 1 DAY)");
      paymentParams.push(`${to} 00:00:00`);

      bookingConditions.push("b.created_at < DATE_ADD(?, INTERVAL 1 DAY)");
      bookingParams.push(`${to} 00:00:00`);
    }

    const paymentWhere = paymentConditions.length
      ? `WHERE ${paymentConditions.join(" AND ")}`
      : "";

    const bookingWhere = bookingConditions.length
      ? `WHERE ${bookingConditions.join(" AND ")}`
      : "";

    const [paymentSummary] = await db.execute<RowDataPacket[]>(
      `SELECT
         COUNT(*) AS total_payments,
         COALESCE(SUM(CASE WHEN p.status = 'pending' THEN 1 ELSE 0 END), 0)
           AS pending_payments,
         COALESCE(SUM(CASE WHEN p.status = 'verified' THEN 1 ELSE 0 END), 0)
           AS verified_payments,
         COALESCE(SUM(CASE WHEN p.status = 'rejected' THEN 1 ELSE 0 END), 0)
           AS rejected_payments,
         COALESCE(SUM(
           CASE WHEN p.status = 'verified' THEN p.amount ELSE 0 END
         ), 0) AS verified_revenue
       FROM payments p
       ${paymentWhere}`,
      paymentParams
    );

    const [bookingSummary] = await db.execute<RowDataPacket[]>(
      `SELECT
         COUNT(*) AS total_bookings,
         COALESCE(SUM(
           CASE WHEN b.status = 'confirmed' THEN 1 ELSE 0 END
         ), 0) AS confirmed_bookings,
         COALESCE(SUM(
           CASE WHEN b.status = 'pending' THEN 1 ELSE 0 END
         ), 0) AS pending_bookings,
         COALESCE(SUM(
           CASE WHEN b.status = 'cancelled' THEN 1 ELSE 0 END
         ), 0) AS cancelled_bookings,
         COALESCE(SUM(b.visitor_count), 0) AS total_visitors
       FROM bookings b
       ${bookingWhere}`,
      bookingParams
    );

    const [transactions] = await db.execute<AdminReportTransaction[]>(
      `SELECT
         p.id AS payment_id,
         b.booking_code,
         u.name AS customer_name,
         u.email AS customer_email,
         b.package_name,
         b.visit_date,
         b.visitor_count,
         p.payment_method,
         p.amount,
         p.status AS payment_status,
         p.rejection_reason,
         p.created_at AS payment_created_at
       FROM payments p
       INNER JOIN bookings b ON b.id = p.booking_id
       INNER JOIN users u ON u.id = b.user_id
       ${paymentWhere}
       ORDER BY p.created_at DESC`,
      paymentParams
    );

    return res.json({
      message: "Laporan berhasil diambil.",
      period: {
        from: from ?? null,
        to: to ?? null,
      },
      summary: {
        bookings: bookingSummary[0],
        payments: paymentSummary[0],
      },
      total_transactions: transactions.length,
      transactions,
    });
  } catch (error) {
    console.error("Gagal mengambil laporan:", error);

    return res.status(500).json({
      message: "Terjadi kesalahan saat mengambil laporan.",
    });
  }
});

// Logout dan cabut token dari database
app.post("/api/admin/logout", authenticateToken, async (_req, res) => {
  try {
    const [result] = await db.execute<ResultSetHeader>(
      `DELETE FROM admin_sessions
       WHERE token_hash = ?`,
      [hashToken(res.locals.token as string)],
    );

    if (result.affectedRows === 0) {
      return res.status(401).json({
        message: "Sesi sudah tidak berlaku.",
      });
    }

    return res.json({
      message: "Logout berhasil. Token sudah dicabut.",
    });
  } catch (error) {
    console.error("Logout admin gagal:", error);
    return res.status(500).json({
      message: "Terjadi kesalahan pada server.",
    });
  }
});

// Daftar pengguna dengan pencarian, filter status, dan pagination
app.get("/api/admin/users", authenticateToken, async (req, res) => {
  try {
    const search = String(req.query.search ?? "").trim();
    // Bisa menerima beberapa status dipisah koma, mis. "inactive,blocked".
    const statusList = String(req.query.status ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const role = String(req.query.role ?? "").trim();

    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 10));
    const offset = (page - 1) * limit;

    if (
      statusList.some(
        (value) => !["active", "inactive", "blocked"].includes(value),
      )
    ) {
      return res.status(400).json({
        message: "Filter status tidak valid.",
      });
    }

    if (role && !["admin", "user"].includes(role)) {
      return res.status(400).json({
        message: "Filter role tidak valid.",
      });
    }

    if (!Number.isSafeInteger(offset)) {
      return res.status(400).json({
        message: "Nomor halaman tidak valid.",
      });
    }

    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (role) {
      conditions.push("role = ?");
      params.push(role);
    }

    if (search) {
      conditions.push("(name LIKE ? OR email LIKE ?)");
      params.push(`%${search}%`, `%${search}%`);
    }

    if (statusList.length > 0) {
      conditions.push(`status IN (${statusList.map(() => "?").join(", ")})`);
      params.push(...statusList);
    }

    if (conditions.length === 0) {
      conditions.push("1 = 1");
    }

    const whereClause = conditions.join(" AND ");

    const [countRows] = await db.execute<CountRow[]>(
      `SELECT COUNT(*) AS total
       FROM users
       WHERE ${whereClause}`,
      params,
    );

    const [users] = await db.execute<ManagedUserRow[]>(
      `SELECT id, name, email, role, status, created_at, updated_at
       FROM users
       WHERE ${whereClause}
       ORDER BY created_at DESC, id DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );

    const total = Number(countRows[0]?.total ?? 0);

    return res.json({
      message: "Daftar pengguna berhasil diambil.",
      data: users,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Gagal mengambil daftar pengguna:", error);

    return res.status(500).json({
      message: "Gagal mengambil daftar pengguna.",
    });
  }
});

// Statistik ringkas pengguna per role (didaftar sebelum route :id
// supaya "stats" tidak tertangkap sebagai nilai :id)
app.get("/api/admin/users/stats", authenticateToken, async (_req, res) => {
  try {
    const [rows] = await db.execute<RowDataPacket[]>(
      `SELECT role, COUNT(*) AS total
       FROM users
       GROUP BY role`,
    );

    const [inactiveRows] = await db.execute<CountRow[]>(
      `SELECT COUNT(*) AS total
       FROM users
       WHERE status IN ('inactive', 'blocked')`,
    );

    const stats = { admin: 0, user: 0, total: 0, inactive: 0 };

    for (const row of rows) {
      const count = Number(row.total ?? 0);

      if (row.role === "admin") stats.admin = count;
      if (row.role === "user") stats.user = count;
      stats.total += count;
    }

    stats.inactive = Number(inactiveRows[0]?.total ?? 0);

    return res.json({
      message: "Statistik pengguna berhasil diambil.",
      data: stats,
    });
  } catch (error) {
    console.error("Gagal mengambil statistik pengguna:", error);

    return res.status(500).json({
      message: "Gagal mengambil statistik pengguna.",
    });
  }
});

// Detail satu pengguna
app.get("/api/admin/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!Number.isSafeInteger(userId) || userId <= 0) {
      return res.status(400).json({
        message: "ID pengguna tidak valid.",
      });
    }

    const [users] = await db.execute<ManagedUserRow[]>(
      `SELECT id, name, email, role, status, created_at, updated_at
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [userId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        message: "Pengguna tidak ditemukan.",
      });
    }

    return res.json({
      message: "Detail pengguna berhasil diambil.",
      data: users[0],
    });
  } catch (error) {
    console.error("Gagal mengambil detail pengguna:", error);

    return res.status(500).json({
      message: "Gagal mengambil detail pengguna.",
    });
  }
});

// Mengubah status akun pengguna
app.patch(
  "/api/admin/users/:id/status",
  authenticateToken,
  async (req, res) => {
    try {
      const userId = Number(req.params.id);
      const status = String(req.body?.status ?? "");

      if (!Number.isSafeInteger(userId) || userId <= 0) {
        return res.status(400).json({
          message: "ID pengguna tidak valid.",
        });
      }

      if (!["active", "inactive", "blocked"].includes(status)) {
        return res.status(400).json({
          message: "Status harus active, inactive, atau blocked.",
        });
      }

      const [result] = await db.execute<ResultSetHeader>(
        `UPDATE users
         SET status = ?, updated_at = NOW()
         WHERE id = ?`,
        [status, userId],
      );

      if (result.affectedRows === 0) {
        const [users] = await db.execute<ManagedUserRow[]>(
          `SELECT id, status
           FROM users
           WHERE id = ?
           LIMIT 1`,
          [userId],
        );

        const user = users[0];

        if (!user) {
          return res.status(404).json({
            message: "Pengguna tidak ditemukan.",
          });
        }

        // Status mungkin memang sudah sesuai dengan permintaan.
        return res.json({
          message: "Status pengguna sudah sesuai.",
          data: {
            id: user.id,
            status: user.status,
          },
        });
      }

      const [users] = await db.execute<ManagedUserRow[]>(
        `SELECT id, name, email, role, status, created_at, updated_at
         FROM users
         WHERE id = ?
         LIMIT 1`,
        [userId],
      );

      return res.json({
        message: "Status pengguna berhasil diperbarui.",
        data: users[0],
      });
    } catch (error) {
      console.error("Gagal mengubah status pengguna:", error);

      return res.status(500).json({
        message: "Gagal mengubah status pengguna.",
      });
    }
  },
);

// Mengubah data pengguna (nama, email, role)
app.patch("/api/admin/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const name =
      typeof req.body?.name === "string" ? req.body.name.trim() : undefined;
    const email =
      typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase()
        : undefined;
    const role =
      typeof req.body?.role === "string" ? req.body.role : undefined;

    if (!Number.isSafeInteger(userId) || userId <= 0) {
      return res.status(400).json({
        message: "ID pengguna tidak valid.",
      });
    }

    if (
      (name !== undefined && (name.length === 0 || name.length > 100)) ||
      (email !== undefined &&
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) ||
      (role !== undefined && !["admin", "user"].includes(role))
    ) {
      return res.status(400).json({
        message: "Data pengguna tidak valid.",
      });
    }

    const sets: string[] = [];
    const params: (string | number)[] = [];

    if (name !== undefined) {
      sets.push("name = ?");
      params.push(name);
    }

    if (email !== undefined) {
      sets.push("email = ?");
      params.push(email);
    }

    if (role !== undefined) {
      sets.push("role = ?");
      params.push(role);
    }

    if (sets.length === 0) {
      return res.status(400).json({
        message: "Tidak ada perubahan data yang dikirim.",
      });
    }

    sets.push("updated_at = NOW()");

    try {
      await db.execute(
        `UPDATE users
         SET ${sets.join(", ")}
         WHERE id = ?`,
        [...params, userId],
      );
    } catch (error: unknown) {
      // ER_DUP_ENTRY: email sudah dipakai pengguna lain.
      if (
        typeof error === "object" &&
        error !== null &&
        (error as { code?: string }).code === "ER_DUP_ENTRY"
      ) {
        return res.status(409).json({
          message: "Email sudah digunakan pengguna lain.",
        });
      }

      throw error;
    }

    const [users] = await db.execute<ManagedUserRow[]>(
      `SELECT id, name, email, role, status, created_at, updated_at
       FROM users
       WHERE id = ? AND role IN ('admin', 'user')
       LIMIT 1`,
      [userId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        message: "Pengguna tidak ditemukan.",
      });
    }

    return res.json({
      message: "Data pengguna berhasil diperbarui.",
      data: users[0],
    });
  } catch (error) {
    console.error("Gagal memperbarui pengguna:", error);

    return res.status(500).json({
      message: "Gagal memperbarui pengguna.",
    });
  }
});

// Katalog paket publik untuk halaman landing (tanpa autentikasi)
app.get("/api/packages", async (_req, res) => {
  try {
    const packages = await prisma.packages.findMany({
      where: { status: "active" },
      orderBy: { id: "asc" },
      select: {
        id: true,
        name: true,
        description: true,
        price: true,
      },
    });

    return res.json({
      message: "Daftar paket berhasil diambil.",
      total: packages.length,
      data: packages.map((item) => ({
        ...item,
        price: item.price.toString(),
      })),
    });
  } catch (error) {
    console.error("Gagal mengambil daftar paket:", error);

    return res.status(500).json({
      message: "Gagal mengambil daftar paket.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Backend berjalan di http://localhost:${PORT}`);
});
