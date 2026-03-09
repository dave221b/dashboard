import { PrismaClient } from '@prisma/client';
import { MetricType } from '../src/metrics/metric-type.enum';

const prisma = new PrismaClient();

async function main() {
  const user = await prisma.user.findFirst();

  if (!user) {
    console.log('No user found. Skipping metrics seed.');
    return;
  }

  const now = new Date();

  const metrics = Array.from({ length: 30 }).map((_, i) => ({
    userId: user.id,
    type: MetricType.ACTIVE_USERS,
    value: Math.floor(Math.random() * 100) + 20,
    timestamp: new Date(now.getTime() - i * 86400000),
  }));

  await prisma.metric.createMany({ data: metrics });

  console.log('Metrics seeded successfully');
}

main()
  .catch((e) => {
    console.error(e);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });