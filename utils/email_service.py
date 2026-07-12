import smtplib
from email.message import EmailMessage
import ssl
from config import Config
from utils.logger import log_audit

class EmailService:
    @staticmethod
    def send_otp_email(username: str, user_email: str, otp_code: str) -> bool:
        """
        Sends the OTP via email to the user using SMTP.
        Returns True if successful, False otherwise.
        """
        subject = "Aegis-Gate Device Verification OTP"
        
        body_text = f"""Hello {username},

A new device is requesting access to your account.

Your One-Time Password is:

{otp_code}

This OTP will expire in 5 minutes.

If you did not request this verification, please ignore this email.

Regards,
Aegis-Gate Security System"""

        body_html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <h2>Hello {username},</h2>
            <p>A new device is requesting access to your account.</p>
            <p>Your One-Time Password is:</p>
            <h1 style="color: #007bff; letter-spacing: 5px;">{otp_code}</h1>
            <p>This OTP will expire in 5 minutes.</p>
            <p>If you did not request this verification, please ignore this email.</p>
            <br>
            <p>Regards,<br><strong>Aegis-Gate Security System</strong></p>
          </body>
        </html>
        """

        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_FROM
        msg['To'] = user_email
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype='html')

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP(Config.EMAIL_HOST, Config.EMAIL_PORT) as server:
                server.starttls(context=context)
                server.login(Config.EMAIL_USERNAME, Config.EMAIL_PASSWORD)
                server.send_message(msg)
            return True
        except Exception as e:
            # Log the error but don't crash
            import logging
            logger = logging.getLogger("aegis.audit")
            logger.error(f"SMTP Error: {str(e)}")
            return False
