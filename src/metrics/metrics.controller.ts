import {
    Controller,
    Post,
    Get,
    Query,
    UseGuards,
    BadRequestException,
  } from '@nestjs/common';
  import { MetricsService } from './metrics.service';
  import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
  import { CurrentUser } from '../common/decorators/current-user.decorator';
  import { MetricType } from './metric-type.enum';
  
  @Controller('metrics')
  export class MetricsController {
    constructor(private metricsService: MetricsService) {}
  
    @UseGuards(JwtAuthGuard)
    @Post('seed')
    seed(@CurrentUser() user: any) {
      return this.metricsService.seed(user.userId);
    }
  
    @UseGuards(JwtAuthGuard)
    @Get()
    getMetrics(
      @CurrentUser() user: any,
      @Query('type') type: string,
    ) {
      if (!(type in MetricType)) {
        throw new BadRequestException('Invalid metric type');
      }
  
      return this.metricsService.getMetrics(user.userId, type as MetricType);
    }
  }