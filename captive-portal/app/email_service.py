"""
Email service for sending notifications via Microsoft Graph API
"""

import os
import logging
import json
import msal
import requests

logger = logging.getLogger(__name__)

# Microsoft Graph API configuration
GRAPH_TENANT_ID = os.getenv('GRAPH_TENANT_ID')  # Azure AD Tenant ID
GRAPH_CLIENT_ID = os.getenv('GRAPH_CLIENT_ID')  # App Registration Client ID
GRAPH_CLIENT_SECRET = os.getenv('GRAPH_CLIENT_SECRET')  # App Registration Secret
GRAPH_FROM_EMAIL = os.getenv('GRAPH_FROM_EMAIL')  # Email address to send from
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

# Microsoft Graph API endpoints
GRAPH_AUTHORITY = f'https://login.microsoftonline.com/{GRAPH_TENANT_ID}'
GRAPH_SCOPE = ['https://graph.microsoft.com/.default']
GRAPH_ENDPOINT = 'https://graph.microsoft.com/v1.0'


def get_graph_access_token():
    """
    Get access token for Microsoft Graph API using client credentials flow.
    
    Returns:
        str: Access token or None if authentication fails
    """
    if not all([GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET]):
        logger.warning("Microsoft Graph credentials not configured")
        return None
    
    try:
        app = msal.ConfidentialClientApplication(
            GRAPH_CLIENT_ID,
            authority=GRAPH_AUTHORITY,
            client_credential=GRAPH_CLIENT_SECRET
        )
        
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
        
        if 'access_token' in result:
            return result['access_token']
        else:
            logger.error(f"Failed to acquire token: {result.get('error_description')}")
            return None
            
    except Exception as e:
        logger.error(f"Error getting Graph access token: {e}")
        return None


def send_email(to_email, subject, html_body, text_body=None):
    """
    Send an email via Microsoft Graph API
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML email body
        text_body: Plain text email body (optional, falls back to HTML if not provided)
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not GRAPH_FROM_EMAIL:
        logger.warning("Microsoft Graph not configured (GRAPH_FROM_EMAIL missing), skipping email")
        return False
    
    try:
        # Get access token
        access_token = get_graph_access_token()
        if not access_token:
            logger.error("Failed to get Microsoft Graph access token")
            return False
        
        # Build email message
        email_message = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": html_body
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": to_email
                        }
                    }
                ]
            },
            "saveToSentItems": "true"
        }
        
        # Send via Graph API
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Use sendMail endpoint
        send_url = f"{GRAPH_ENDPOINT}/users/{GRAPH_FROM_EMAIL}/sendMail"
        
        response = requests.post(
            send_url,
            headers=headers,
            data=json.dumps(email_message),
            timeout=30
        )
        
        if response.status_code == 202:  # Accepted
            logger.info(f"Email sent to {to_email}: {subject}")
            return True
        else:
            logger.error(f"Failed to send email: HTTP {response.status_code} - {response.text}")
            return False
        
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


def send_user_blocked_device_notice(to_email, first_name, mac_address, device_name=None):
    """
    Notify a user that their device was registered but access is blocked.
    """
    subject = "Device Registered but Access Blocked"

    device_label = device_name or "your device"
    admin_email = ADMIN_EMAIL or "the administrator"

    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <h2>Hello {first_name},</h2>
        <p>We have registered {device_label} (MAC: <strong>{mac_address}</strong>).</p>
        <p>However, your account is currently <strong>blocked</strong>, so this device cannot access the internet.</p>
        <p>Please contact the administrator to request unblocking.</p>
        <p style="margin: 20px 0;">Administrator contact: <strong>{admin_email}</strong></p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #666; font-size: 12px;">This is an automated message from the Network Access Portal.</p>
    </body>
    </html>
    """

    text_body = f"""
    Hello {first_name},

    We have registered {device_label} (MAC: {mac_address}).
    However, your account is currently blocked, so this device cannot access the internet.

    Please contact the administrator to request unblocking.
    Administrator contact: {admin_email}
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


def send_wifi_registration_confirmation(user_email, first_name, ssid, mac_address, unregister_url, registration_details=None):
    """
    Send WiFi registration confirmation with unregister link
    
    Args:
        user_email: User's email address
        first_name: User's first name
        ssid: WiFi SSID name
        mac_address: Device MAC address
        unregister_url: URL to unregister this device
    """
    subject = f"WiFi Registration Confirmed - {ssid}"
    
    admin_contact_html = (
        f"If you did not register this device, click the unregister button above or email "
        f"<a href=\"mailto:{ADMIN_EMAIL}\">{ADMIN_EMAIL}</a>."
        if ADMIN_EMAIL else
        "If you did not register this device, click the unregister button above or contact the administrator."
    )
    admin_contact_text = (
        f"If you did not register this device, click the unregister link above or email {ADMIN_EMAIL}."
        if ADMIN_EMAIL else
        "If you did not register this device, click the unregister link above or contact the administrator."
    )

    registration_details = registration_details or {}
    details_name = " ".join([
        registration_details.get("first_name", ""),
        registration_details.get("last_name", "")
    ]).strip() or first_name or "Unknown"
    details_phone = registration_details.get("phone_number") or "Not provided"
    details_device_type = registration_details.get("device_type") or "Unknown"
    details_email = registration_details.get("email") or user_email
    details_ip = registration_details.get("ip_address") or "Unknown"
    details_ssid = registration_details.get("ssid") or ssid

    details_html = "".join([
        f"<li><strong>Name:</strong> {details_name}</li>",
        f"<li><strong>Email:</strong> {details_email}</li>",
        f"<li><strong>Phone:</strong> {details_phone}</li>",
        f"<li><strong>Device Type:</strong> {details_device_type}</li>",
        f"<li><strong>MAC Address:</strong> {mac_address}</li>",
        f"<li><strong>IP Address:</strong> {details_ip}</li>",
        f"<li><strong>Network:</strong> {details_ssid}</li>",
    ])

    details_text = "\n".join([
        f"Name: {details_name}",
        f"Email: {details_email}",
        f"Phone: {details_phone}",
        f"Device Type: {details_device_type}",
        f"MAC Address: {mac_address}",
        f"IP Address: {details_ip}",
        f"Network: {details_ssid}",
    ])

    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #1a2b1a 0%, #263326 100%); color: white; padding: 30px; text-align: center;">
                <h1 style="margin: 0; font-size: 28px;">Welcome to {ssid}!</h1>
            </div>
            
            <div style="padding: 30px; background-color: #f9f9f9;">
                <h2 style="color: #263326; margin-top: 0;">Hi {first_name},</h2>
                
                <p style="font-size: 16px;">Your device has been successfully registered on our WiFi network.</p>
                
                <div style="background-color: white; border-left: 4px solid #263326; padding: 15px; margin: 20px 0;">
                    <p style="margin: 0;"><strong>Network:</strong> {ssid}</p>
                    <p style="margin: 10px 0 0; font-family: monospace; font-size: 14px;"><strong>Device:</strong> {mac_address}</p>
                </div>
                
                <div style="background-color: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 20px 0;">
                    <p style="margin: 0; color: #2e7d32;"><strong>✓ Your connection is now active</strong></p>
                    <p style="margin: 10px 0 0; font-size: 14px;">Please wait up to 30 seconds for your device to renew its connection and gain full internet access.</p>
                </div>
                
                <h3 style="color: #263326; margin-top: 30px;">Registration Responsibility</h3>
                
                <p>
                    By registering this device, you are taking responsibility for its internet usage.
                    If you do not recognize this device, please deregister it by clicking the button below
                    or by emailing the administrator.
                </p>

                <div style="background-color: white; border-left: 4px solid #263326; padding: 15px; margin: 20px 0;">
                    <p style="margin: 0;"><strong>Registration details:</strong></p>
                    <ul style="margin: 10px 0 0 18px; padding: 0;">
                        {details_html}
                    </ul>
                </div>
                
                <p style="text-align: center; margin: 25px 0;">
                    <a href="{unregister_url}" 
                       style="background-color: #d32f2f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                        Unregister This Device
                    </a>
                </p>
                
                <p style="font-size: 13px; color: #666; border-top: 1px solid #ddd; padding-top: 15px; margin-top: 30px;">
                    <strong>Important:</strong> Clicking the unregister link will immediately revoke network access for this device. 
                    This prevents someone else from impersonating your device using its MAC address.
                </p>

                <p style="font-size: 13px; color: #666;">{admin_contact_html}</p>
                
                <p style="font-size: 13px; color: #666;">
                    If you experience any connection issues, please contact the network administrator.
                </p>
            </div>
            
            <div style="background-color: #263326; color: #999; padding: 20px; text-align: center; font-size: 12px;">
                <p style="margin: 0;">This is an automated message from Blackfriars Network Access Portal</p>
                <p style="margin: 10px 0 0;">If you didn't register this device, please contact us immediately</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome to {ssid}!
    
    Hi {first_name},
    
    Your device has been successfully registered on our WiFi network.
    
    Network: {ssid}
    Device: {mac_address}
    
    ✓ Your connection is now active
    
    Please wait up to 30 seconds for your device to renew its connection and gain full internet access.
    
    
    REGISTRATION RESPONSIBILITY

    By registering this device, you are taking responsibility for its internet usage.
    If you do not recognize this device, please deregister it using the link below
    or by emailing the administrator.

    Registration details:
    {details_text}
    
    {unregister_url}
    
    Important: Clicking the unregister link will immediately revoke network access for this device.
    This prevents someone else from impersonating your device using its MAC address.

    {admin_contact_text}
    
    If you experience any connection issues, please contact the network administrator.
    
    ---
    This is an automated message from Blackfriars Network Access Portal
    If you didn't register this device, please contact us immediately
    """
    
    return send_email(user_email, subject, html_body, text_body)
