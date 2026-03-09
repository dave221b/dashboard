import { Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { MetricType } from './metric-type.enum';

@Injectable()
export class MetricsService {
  constructor(private prisma: PrismaService) {}

  async seed(userId: string) {
    const now = new Date();

    const data = Array.from({ length: 30 }).map((_, i) => ({
      userId,
      type: MetricType.ACTIVE_USERS,
      value: Math.floor(Math.random() * 100) + 20,
      timestamp: new Date(now.getTime() - i * 86400000),
    }));

    await this.prisma.metric.createMany({ data });

    return { message: 'Metrics seeded' };
  }

  async getMetrics(userId: string, type: MetricType) {
    return this.prisma.metric.findMany({
      where: { userId, type },
      orderBy: { timestamp: 'asc' },
    });
  }
}