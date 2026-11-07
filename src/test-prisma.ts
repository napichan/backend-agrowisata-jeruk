import { prisma } from "./prisma.js";

async function main() {
  const [users, packages, bookings, payments] = await Promise.all([
    prisma.users.count(),
    prisma.packages.count(),
    prisma.bookings.count(),
    prisma.payments.count(),
  ]);

  console.log("Koneksi Prisma berhasil!");
  console.log({ users, packages, bookings, payments });
}

main()
  .catch((error) => {
    console.error("Koneksi Prisma gagal:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
