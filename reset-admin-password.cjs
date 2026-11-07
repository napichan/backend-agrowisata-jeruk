const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const readline = require("node:readline");
const { stdin, stdout } = require("node:process");

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout });

  const password = await new Promise((resolve) => {
    rl.question("Masukkan password admin baru: ", resolve);
  });

  rl.close();

  if (password.length < 8) {
    throw new Error("Password minimal 8 karakter.");
  }

  const hash = await bcrypt.hash(password, 12);

  const conn = await mysql.createConnection({
    host: "127.0.0.1",
    port: 3306,
    user: "root",
    password: "",
    database: "agro_wisata_jeruk"
  });

  try {
    const [result] = await conn.execute(
      "UPDATE users SET password = ?, updated_at = NOW() WHERE email = ? AND role = ? AND status = ?",
      [hash, "admin@agrojeruk.id", "admin", "active"]
    );

    console.log("Jumlah akun admin diperbarui:", result.affectedRows);

    if (result.affectedRows !== 1) {
      throw new Error("Akun admin tidak ditemukan atau tidak berhasil diperbarui.");
    }
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  console.error("Gagal:", err.message);
  process.exitCode = 1;
});
