import { Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { MetricType } from './metric-type.enum';

@Injectable()
export class MetricsService {
  constructor(private prisma: PrismaService) {}

  async seed(userId: string) {
    const now = new Date();

    const metricTypes = [
      MetricType.ACTIVE_USERS,
      MetricType.REVENUE,
      MetricType.SIGNUPS,
    ];
    const data = Array.from({ length: 30 }).flatMap((_, i) => {
      const timestamp = new Date(now.getTime() - i * 86400000);

      return metricTypes.map((type) => ({
        userId,
        type,
        value: Math.floor(Math.random() * 100) + 20,
        timestamp,
      }));
    });

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