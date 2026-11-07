
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { db } from "./db.js";

dotenv.config();

async function seedAdmin() {
  const name = process.env.ADMIN_NAME;
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;

  if (!name || !email || !password) {
    throw new Error("Konfigurasi ADMIN_NAME, ADMIN_EMAIL, atau ADMIN_PASSWORD belum lengkap.");
  }

  if (password.length < 8) {
    throw new Error("Password admin minimal 8 karakter.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    await db.execute(
      `INSERT INTO users (name, email, password)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         name = VALUES(name),
         password = VALUES(password)`,
      [name, email, hashedPassword],
    );

    console.log(`Akun admin ${email} berhasil disiapkan.`);
  } finally {
    await db.end();
  }
}

seedAdmin().catch((error) => {
  console.error("Gagal menyiapkan akun admin:", error.message);
  process.exitCode = 1;
});
