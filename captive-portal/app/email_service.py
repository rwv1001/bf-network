"""
Email service for sending notifications
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

# SMTP configuration
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER)
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')


def send_email(to_email, subject, html_body, text_body=None):
    """
    Send an email
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML email body
        text_body: Plain text email body (optional)
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP not configured, skipping email")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        
        # Add plain text version
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))
        
        # Add HTML version
        msg.attach(MIMEText(html_body, 'html'))
        
        # Connect and send
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Email sent to {to_email}: {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


def send_verification_email(to_email, first_name, verification_url, timeout_minutes):
    """
    Send email verification link to user
    
    Args:
        to_email: User's email address
        first_name: User's first name
        verification_url: Verification link URL
        timeout_minutes: Minutes until link expires
    """
    subject = "Verify Your Network Access"
    
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2>Welcome, {first_name}!</h2>
        
        <p>Thank you for registering your device on our network.</p>
        
        <p>To complete your registration and gain full network access, please click the link below within the next {timeout_minutes} minutes:</p>
        
        <p style="margin: 20px 0;">
            <a href="{verification_url}" 
               style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Verify My Email
            </a>
        </p>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #f5f5f5; padding: 10px; border-left: 3px solid #007bff; word-break: break-all;">
            {verification_url}
        </p>
        
        <p><strong>Important:</strong> If you don't verify within {timeout_minutes} minutes, your device will be placed on a restricted network and you'll need to contact the administrator.</p>
        
        <p>If you didn't request this, please ignore this email or contact the network administrator.</p>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">
            This is an automated message from the Network Access Portal.
        </p>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome, {first_name}!
    
    Thank you for registering your device on our network.
    
    To complete your registration and gain full network access, please visit this link within the next {timeout_minutes} minutes:
    
    {verification_url}
    
    Important: If you don't verify within {timeout_minutes} minutes, your device will be placed on a restricted network and you'll need to contact the administrator.
    
    If you didn't request this, please ignore this email or contact the network administrator.
    """
    
    return send_email(to_email, subject, html_body, text_body)


def send_admin_notification(registration_request, approval_url):
    """
    Send notification to admin about new registration request
    
    Args:
        registration_request: RegistrationRequest object
        approval_url: URL for admin to approve the request
    """
    if not ADMIN_EMAIL:
        logger.warning("ADMIN_EMAIL not configured, skipping admin notification")
        return False
    
    subject = f"New Network Access Request: {registration_request.email}"
    
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2>New Network Access Request</h2>
        
        <p>A new user has requested network access. Please review the details below:</p>
        
        <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Name:</td>
                <td style="padding: 8px;">{registration_request.full_name}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Email:</td>
                <td style="padding: 8px;">{registration_request.email}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Phone:</td>
                <td style="padding: 8px;">{registration_request.phone_number or 'Not provided'}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">MAC Address:</td>
                <td style="padding: 8px; font-family: monospace;">{registration_request.mac_address}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">IP Address:</td>
                <td style="padding: 8px;">{registration_request.ip_address}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Submitted:</td>
                <td style="padding: 8px;">{registration_request.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
        </table>
        
        <p style="margin: 20px 0;">
            <a href="{approval_url}" 
               style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Review and Approve
            </a>
        </p>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #f5f5f5; padding: 10px; border-left: 3px solid #28a745; word-break: break-all;">
            {approval_url}
        </p>
        
        <p><strong>Action Required:</strong> Please contact the user to verify their identity before approving access.</p>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">
            This is an automated message from the Network Access Portal.
        </p>
    </body>
    </html>
    """
    
    text_body = f"""
    New Network Access Request
    
    A new user has requested network access. Please review the details below:
    
    Name: {registration_request.full_name}
    Email: {registration_request.email}
    Phone: {registration_request.phone_number or 'Not provided'}
    MAC Address: {registration_request.mac_address}
    IP Address: {registration_request.ip_address}
    Submitted: {registration_request.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}
    
    To review and approve this request, visit:
    {approval_url}
    
    Action Required: Please contact the user to verify their identity before approving access.
    """
    
    return send_email(ADMIN_EMAIL, subject, html_body, text_body)


def send_approval_notification(user_email, first_name, status):
    """
    Send notification to user that their access has been approved
    
    Args:
        user_email: User's email address
        first_name: User's first name
        status: Access level granted (staff, students, etc.)
    """
    subject = "Network Access Approved"
    
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2>Welcome, {first_name}!</h2>
        
        <p>Your network access request has been approved.</p>
        
        <p><strong>Access Level:</strong> {status.title()}</p>
        
        <p>Your device should now have full network access. If you experience any issues, please contact the network administrator.</p>
        
        <p>Thank you!</p>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">
            This is an automated message from the Network Access Portal.
        </p>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome, {first_name}!
    
    Your network access request has been approved.
    
    Access Level: {status.title()}
    
    Your device should now have full network access. If you experience any issues, please contact the network administrator.
    
    Thank you!
    """
    
    return send_email(user_email, subject, html_body, text_body)
