import { Response } from 'express';
import { ApiResponse } from '../types';

export class ResponseUtil {
  public static success<T>(
    res: Response,
    data: T,
    message = 'Operation successful',
    statusCode = 200
  ): Response {
    const payload: ApiResponse<T> = {
      success: true,
      message,
      data,
      timestamp: new Date().toISOString(),
    };
    return res.status(statusCode).json(payload);
  }

  public static created<T>(
    res: Response,
    data: T,
    message = 'Resource created successfully'
  ): Response {
    return this.success(res, data, message, 201);
  }

  public static error(
    res: Response,
    message: string,
    statusCode = 400,
    code = 'BAD_REQUEST',
    details?: unknown
  ): Response {
    const payload: ApiResponse = {
      success: false,
      error: {
        code,
        message,
        details,
      },
      timestamp: new Date().toISOString(),
    };
    return res.status(statusCode).json(payload);
  }
}
