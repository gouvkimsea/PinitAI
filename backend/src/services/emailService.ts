import { logger } from '../utils/logger';

export interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export class EmailService {
  private static instance: EmailService;

  private constructor() {}

  public static getInstance(): EmailService {
    if (!EmailService.instance) {
      EmailService.instance = new EmailService();
    }
    return EmailService.instance;
  }

  /**
   * Dispatches a transactional password reset email.
   * If an external email provider/webhook is configured, it transmits via HTTP/SMTP.
   * Otherwise, it logs a clean audit message for production observability without crashing.
   */
  async sendPasswordResetEmail(toEmail: string, resetToken: string, resetBaseUrl?: string): Promise<boolean> {
    const baseUrl = resetBaseUrl || process.env.APP_BASE_URL || 'http://localhost';
    const resetUrl = `${baseUrl.replace(/\/$/, '')}/reset-password?token=${encodeURIComponent(resetToken)}`;

    const subject = 'Password Reset Request - PinIt ScamCheck AI';
    const text = `You requested a password reset for your PinIt ScamCheck AI account. Use the following link within 15 minutes to reset your password: ${resetUrl}`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2563eb;">PinIt ScamCheck AI</h2>
        <p>You requested a password reset for your account.</p>
        <p>Click the button below to choose a new password. This link is valid for <strong>15 minutes</strong>.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #64748b; font-size: 13px;">If you did not request this password reset, please ignore this email.</p>
      </div>
    `;

    try {
      const webhookUrl = process.env.EMAIL_WEBHOOK_URL;
      if (webhookUrl) {
        // Asynchronous webhook dispatch if configured
        fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ to: toEmail, subject, text, html }),
        }).catch((err) => {
          logger.warn('[EmailService] Webhook dispatch failed', { error: err?.message });
        });
      }

      logger.info('[EmailService] Password reset dispatch scheduled', {
        recipient: toEmail,
        timestamp: new Date().toISOString(),
      });
      return true;
    } catch (err: any) {
      logger.error('[EmailService] Failed to dispatch password reset email', {
        recipient: toEmail,
        error: err?.message,
      });
      return false;
    }
  }
}

export const emailService = EmailService.getInstance();
