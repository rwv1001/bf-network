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


def send_admin_unblock_request(mac_address, ip_address, user_name=None, user_email=None):
    """
    Notify all manage_users admins that a blocked device's user is requesting removal of the block.
    """
    from models import Admin

    admins = Admin.query.filter(
        Admin.can_manage_users == True,
        Admin.email != None,
        Admin.email != ''
    ).all()

    if not admins:
        if not ADMIN_EMAIL:
            logger.warning("No admin emails configured for unblock request")
            return 0
        admins_to_email = [{'email': ADMIN_EMAIL, 'username': 'Admin'}]
    else:
        admins_to_email = [{'email': a.email, 'username': a.username} for a in admins]

    user_display = user_name or user_email or 'Unknown user'
    subject = f"Unblock Request from {user_display}"

    emails_sent = 0
    for admin_info in admins_to_email:
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Unblock Request</h2>
            <p>Hello {admin_info['username']},</p>
            <p>A blocked device is requesting removal of its internet block.</p>
            <table style="border-collapse: collapse; margin: 20px 0;">
                <tr><td style="padding:8px;font-weight:bold;background:#f5f5f5;">MAC Address:</td>
                    <td style="padding:8px;font-family:monospace;">{mac_address}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;background:#f5f5f5;">IP Address:</td>
                    <td style="padding:8px;">{ip_address or 'Unknown'}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;background:#f5f5f5;">User:</td>
                    <td style="padding:8px;">{user_display}</td></tr>
            </table>
            <p>Please log in to the admin dashboard to review and respond to this request.</p>
            <hr style="margin:30px 0;border:none;border-top:1px solid #ddd;">
            <p style="color:#666;font-size:12px;">This is an automated message from the Network Access Portal.</p>
        </body>
        </html>
        """
        text_body = (
            f"Unblock Request\n\nMAC: {mac_address}\nIP: {ip_address or 'Unknown'}\n"
            f"User: {user_display}\n\nPlease log in to the admin dashboard to review."
        )
        if send_email(admin_info['email'], subject, html_body, text_body):
            emails_sent += 1
    return emails_sent


def send_admin_notification(registration_request, approval_url, current_vlan=None, current_ssid=None):
    """
    Send notification to all admins with manage_users permission about new registration request
    
    Args:
        registration_request: RegistrationRequest object
        approval_url: URL for admin to approve the request
    Returns:
        int: Number of emails sent successfully
    """
    # Import Admin model here to avoid circular imports
    from models import Admin
    
    # Get all admins with manage_users permission and a valid email
    admins = Admin.query.filter(
        Admin.can_manage_users == True,
        Admin.email != None,
        Admin.email != ''
    ).all()
    
    if not admins:
        logger.warning("No admins with manage_users permission and email configured, trying fallback ADMIN_EMAIL")
        # Fallback to old ADMIN_EMAIL env var
        if not ADMIN_EMAIL:
            logger.warning("No admin emails configured at all, skipping admin notification")
            return 0
        admins_to_email = [{'email': ADMIN_EMAIL, 'username': 'Admin'}]
    else:
        admins_to_email = [{'email': admin.email, 'username': admin.username} for admin in admins]
    
    subject = f"New Network Access Request: {registration_request.email}"
    
    emails_sent = 0
    for admin_info in admins_to_email:
        admin_email = admin_info['email']
        admin_username = admin_info['username']
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>New Network Access Request</h2>
            
            <p>Hello {admin_username},</p>
            
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
                    <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Connected VLAN:</td>
                    <td style="padding: 8px;">{current_vlan or 'Unknown'}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Connected SSID:</td>
                    <td style="padding: 8px;">{current_ssid or 'Unknown'}</td>
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
            
            <p style="color: #999; font-size: 14px; margin-top: 20px;">
                <em>Note: This request has been sent to all admins with user management permissions. The first admin to process this request will determine the outcome.</em>
            </p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
            <p style="color: #666; font-size: 12px;">
                This is an automated message from the Network Access Portal.
            </p>
        </body>
        </html>
        """
        
        text_body = f"""
        New Network Access Request
        
        Hello {admin_username},
        
        A new user has requested network access. Please review the details below:
        
        Name: {registration_request.full_name}
        Email: {registration_request.email}
        Phone: {registration_request.phone_number or 'Not provided'}
        MAC Address: {registration_request.mac_address}
        IP Address: {registration_request.ip_address}
        Connected VLAN: {current_vlan or 'Unknown'}
        Connected SSID: {current_ssid or 'Unknown'}
        Submitted: {registration_request.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}
        
        To review and approve this request, visit:
        {approval_url}
        
        Note: This request has been sent to all admins with user management permissions. 
        The first admin to process this request will determine the outcome.
        """
        
        # Send email to this admin
        if send_email(admin_email, subject, html_body, text_body):
            emails_sent += 1
            logger.info(f"Sent admin notification to {admin_email} ({admin_username})")
        else:
            logger.error(f"Failed to send admin notification to {admin_email} ({admin_username})")
    
    logger.info(f"Sent {emails_sent}/{len(admins_to_email)} admin notifications for request {registration_request.id}")
    return emails_sent


def send_admin_password_setup_email(registration_request, set_password_url, current_vlan=None, current_ssid=None):
    """
    Send all manage_users admins a link to set a network password for a pending_password request.
    The link goes to the admin-only /admin/set-user-password/<token> page where the admin
    can set the password on behalf of the user and choose an approval policy.
    """
    from models import Admin

    admins = Admin.query.filter(
        Admin.can_manage_users == True,
        Admin.email != None,
        Admin.email != ''
    ).all()

    if not admins:
        fallback = os.getenv('ADMIN_EMAIL', '')
        if not fallback:
            logger.warning("No admin emails configured; skipping password-setup notification")
            return 0
        admins_to_email = [{'email': fallback, 'username': 'Admin'}]
    else:
        admins_to_email = [{'email': a.email, 'username': a.username} for a in admins]

    subject = f"Action Required – Set Network Password for {registration_request.email}"

    emails_sent = 0
    for admin_info in admins_to_email:
        admin_email = admin_info['email']
        admin_username = admin_info['username']

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color:#1e5128;">Network Password Setup Required</h2>

            <p>Hello {admin_username},</p>

            <p>A user has requested network access on a VLAN that requires a network password,
            but no password has been set for them yet.
            Please click the button below to set their password.</p>

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
                    <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">VLAN / SSID:</td>
                    <td style="padding: 8px;">{current_vlan or 'Unknown'} / {current_ssid or 'Unknown'}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; font-weight: bold; background-color: #f5f5f5;">Submitted:</td>
                    <td style="padding: 8px;">{registration_request.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
            </table>

            <p style="margin: 24px 0;">
                <a href="{set_password_url}"
                   style="background-color:#1e5128; color:white; padding:12px 24px; text-decoration:none;
                          border-radius:5px; display:inline-block; font-weight:bold;">
                    Set Password
                </a>
            </p>

            <p>Or copy and paste this link into your browser:</p>
            <p style="background-color:#f5f5f5; padding:10px; border-left:3px solid #1e5128;
                      word-break:break-all; font-size:13px;">
                {set_password_url}
            </p>

            <p style="color:#999; font-size:13px; margin-top:20px;">
                <em>This request has been sent to all admins with user management permissions.
                The first admin to act will determine the outcome.</em>
            </p>

            <hr style="margin:30px 0; border:none; border-top:1px solid #ddd;">
            <p style="color:#666; font-size:12px;">
                This is an automated message from the Network Access Portal.
            </p>
        </body>
        </html>
        """

        text_body = f"""Action Required – Set Network Password

Hello {admin_username},

A user has requested network access on a VLAN that requires a network password,
but no password has been set for them yet. Please click the link below to set their password.

Name:     {registration_request.full_name}
Email:    {registration_request.email}
Phone:    {registration_request.phone_number or 'Not provided'}
MAC:      {registration_request.mac_address}
VLAN:     {current_vlan or 'Unknown'}
SSID:     {current_ssid or 'Unknown'}

Set their password here:
{set_password_url}
"""
        if send_email(admin_email, subject, html_body, text_body):
            emails_sent += 1
            logger.info("Sent admin password-setup notification to %s", admin_email)
        else:
            logger.error("Failed to send admin password-setup notification to %s", admin_email)

    return emails_sent


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


def send_wifi_registration_confirmation(
    user_email,
    first_name,
    ssid,
    mac_address,
    unregister_url,
    registration_details=None,
    confirm_url=None,
    reject_url=None,
    confirm_timeout_sec=None,
):
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

    confirm_timeout_minutes = None
    if confirm_timeout_sec:
        confirm_timeout_minutes = max(1, int((int(confirm_timeout_sec) + 59) / 60))

    confirm_html = ""
    confirm_text = ""
    if confirm_url:
        timeout_note_html = ""
        timeout_note_text = ""
        if confirm_timeout_minutes:
            timeout_note_html = (
                f"<p style=\"margin-top: 10px; font-size: 14px;\">"
                f"Please confirm within <strong>{confirm_timeout_minutes} minutes</strong> "
                f"to keep this device active. If you do not confirm, the device will be "
                f"automatically blocked.</p>"
            )
            timeout_note_text = (
                f"Please confirm within {confirm_timeout_minutes} minutes to keep this device active. "
                f"If you do not confirm, the device will be automatically blocked."
            )
        reject_btn_html = ""
        reject_btn_text = ""
        if reject_url:
            reject_btn_html = (
                f"<a href=\"{reject_url}\" "
                f"style=\"background-color: #c62828; color: white; padding: 12px 30px; "
                f"text-decoration: none; border-radius: 5px; display: inline-block; "
                f"font-weight: bold; margin-left: 12px;\">Block This Device</a>"
            )
            reject_btn_text = f"\n    Block this device (did not register / reject access):\n    {reject_url}"
        confirm_html = f"""
                <div style=\"background-color: white; border-left: 4px solid #1b5e20; padding: 15px; margin: 20px 0;\">
                    <p style=\"margin: 0;\"><strong>Confirm this device</strong></p>
                    <p style=\"margin: 10px 0 0; font-size: 14px;\">Click <em>Accept</em> if you registered this device, or <em>Block</em> if you did not.</p>
                    {timeout_note_html}
                    <p style=\"text-align: center; margin: 15px 0 0;\">
                        <a href=\"{confirm_url}\"
                           style=\"background-color: #2e7d32; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;\">
                            Accept and Keep Access
                        </a>
                        {reject_btn_html}
                    </p>
                </div>
        """
        confirm_text = f"""
    CONFIRM THIS DEVICE
    Click the link below to accept this device:
    {confirm_url}
    {timeout_note_text}{reject_btn_text}
    """

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

                {confirm_html}
                
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

    {confirm_text}
    
    
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


def send_vlan_mismatch_notification(
    user_email,
    first_name,
    requested_ssid,
    assigned_ssid,
    mac_address,
    unregister_url,
):
    """
    Notify a user that the administrator has assigned them to a different
    network than the one they requested (spec 4b.ii.2.c).
    """
    subject = f"Network Access Decision – Please Connect to {assigned_ssid}"

    admin_contact_html = (
        f"If you have questions, email <a href=\"mailto:{ADMIN_EMAIL}\">{ADMIN_EMAIL}</a>."
        if ADMIN_EMAIL else
        "If you have questions, please contact the administrator."
    )
    admin_contact_text = (
        f"If you have questions, email {ADMIN_EMAIL}."
        if ADMIN_EMAIL else
        "If you have questions, please contact the administrator."
    )

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #1a2b1a, #263326); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">Blackfriars Network</h1>
            <p style="margin: 10px 0 0; opacity: 0.9;">Network Access Decision</p>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px;">
            <p>Hi {first_name},</p>
            <p>The administrator has reviewed your request to access <strong>{requested_ssid}</strong>.</p>
            <p>You have been granted access to a different network instead:</p>
            <div style="background: #e8f5e9; border-left: 4px solid #2e7d32; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <p style="margin: 0; font-size: 18px; font-weight: bold; color: #1b5e20;">
                    Please connect to: {assigned_ssid}
                </p>
                <p style="margin: 8px 0 0; font-size: 14px; color: #555;">
                    Device MAC address: {mac_address}
                </p>
            </div>
            <p>To gain internet access, disconnect from <strong>{requested_ssid}</strong> and connect to <strong>{assigned_ssid}</strong>.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="font-size: 14px; color: #666;">
                If you did not make this registration request, you can
                <a href="{unregister_url}" style="color: #8B0000;">unregister this device</a>.
            </p>
            <p style="font-size: 14px; color: #666;">{admin_contact_html}</p>
        </div>
    </div>
    """

    text_body = f"""
Hi {first_name},

The administrator has reviewed your request to access {requested_ssid}.

You have been granted access to a different network instead.

Please connect to: {assigned_ssid}
Device MAC address: {mac_address}

To gain internet access, disconnect from {requested_ssid} and connect to {assigned_ssid}.

If you did not make this request, unregister this device: {unregister_url}
{admin_contact_text}
    """

    return send_email(user_email, subject, html_body, text_body)


def send_admin_password_reset_email(admin_email, admin_username, reset_url):
    """
    Send a password reset link to an admin user.

    Args:
        admin_email: Admin's email address
        admin_username: Admin's username (for personalisation)
        reset_url: Full URL of the reset link (expires in 1 hour)

    Returns:
        bool: True if sent successfully, False otherwise
    """
    subject = "Admin Password Reset – Blackfriars Network Portal"

    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(90deg,#2c7a7b,#3a9e9e); padding: 24px 28px; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 22px;">Password Reset Request</h1>
        </div>
        <div style="background: #f9f9f9; padding: 28px; border: 1px solid #dde2e8; border-top: none; border-radius: 0 0 8px 8px;">
            <p>Hi <strong>{admin_username}</strong>,</p>
            <p>We received a request to reset the password for your administrator account on the
               <strong>Blackfriars Network Portal</strong>.</p>
            <p>Click the button below to choose a new password. This link is valid for <strong>1 hour</strong>.</p>
            <div style="text-align: center; margin: 32px 0;">
                <a href="{reset_url}"
                   style="background: #2c7a7b; color: white; padding: 13px 30px; border-radius: 6px;
                          text-decoration: none; font-size: 15px; font-weight: bold;">
                    Reset My Password
                </a>
            </div>
            <p style="font-size: 13px; color: #666;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href="{reset_url}" style="color: #2c7a7b;">{reset_url}</a>
            </p>
            <hr style="border: none; border-top: 1px solid #dde2e8; margin: 24px 0;">
            <p style="font-size: 13px; color: #888;">
                If you didn't request a password reset, you can safely ignore this email.
                Your password will not change unless you follow the link above.
            </p>
            <p style="font-size: 12px; color: #aaa; margin-top: 20px;">
                This is an automated message from Blackfriars Network Access Portal
            </p>
        </div>
    </body></html>
    """

    text_body = f"""Password Reset Request – Blackfriars Network Portal

Hi {admin_username},

We received a request to reset the password for your administrator account.

Click the link below to choose a new password (valid for 1 hour):

{reset_url}

If you didn't request a password reset, you can safely ignore this email.

---
This is an automated message from Blackfriars Network Access Portal
"""

    return send_email(admin_email, subject, html_body, text_body)


def send_network_password_set_email(to_email, first_name, set_password_url, expiry_hours=24, network_name=None):
    """
    Send a network password setup link to a user who needs to create a portal password.

    Args:
        to_email: User's email address
        first_name: User's first name
        set_password_url: Full URL of the set-password page
        expiry_hours: Hours until link expires (default 24)
        network_name: SSID or network description shown to the user (e.g. 'BF-Staff' or 'Wired Network')
    """
    subject = "Set Your Network Password – Blackfriars Network Portal"
    network_display = network_name or 'the network'

    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(90deg,#2c7a7b,#3a9e9e); padding: 24px 28px; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 22px;">Set Your Network Password</h1>
        </div>
        <div style="background: #f9f9f9; padding: 28px; border: 1px solid #dde2e8; border-top: none; border-radius: 0 0 8px 8px;">
            <p>Hello <strong>{first_name}</strong>,</p>
            <p>Thank you for attempting to logon to the network <strong>{network_display}</strong>.
               In order to gain access, you will need to set a password by following the link below.</p>
            <p>If you have already been given a password by the network administrator,
               please ignore this email.</p>
            <p style="font-size: 13px; color: #888;">This link is valid for <strong>{expiry_hours} hours</strong>.</p>
            <div style="text-align: center; margin: 32px 0;">
                <a href="{set_password_url}"
                   style="background: #2c7a7b; color: white; padding: 13px 30px; border-radius: 6px;
                          text-decoration: none; font-size: 15px; font-weight: bold;">
                    Set My Network Password
                </a>
            </div>
            <p style="font-size: 13px; color: #666;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href="{set_password_url}" style="color: #2c7a7b; word-break: break-all;">{set_password_url}</a>
            </p>
            <hr style="border: none; border-top: 1px solid #dde2e8; margin: 24px 0;">
            <p style="font-size: 13px; color: #888;">
                Once you've set your password, return to the network registration page on the
                device you want to connect and enter it when prompted.
            </p>
            <p style="font-size: 12px; color: #aaa; margin-top: 20px;">
                This is an automated message from Blackfriars Network Access Portal
            </p>
        </div>
    </body></html>
    """

    text_body = f"""Set Your Network Password – Blackfriars Network Portal

Hello {first_name},

Thank you for attempting to logon to the network {network_display}.
In order to gain access, you will need to set a password by following the link below.

If you have already been given a password by the network administrator, please ignore this email.

Set your password here (valid for {expiry_hours} hours):
{set_password_url}

Once you've set your password, return to the network registration page on the
device you want to connect and enter it when prompted.

---
This is an automated message from Blackfriars Network Access Portal
"""

    return send_email(to_email, subject, html_body, text_body)


def send_network_password_reset_email(to_email, first_name, reset_url, expiry_hours=24):
    """
    Send a password-reset link to a user who has forgotten their network password.

    Args:
        to_email: User's email address
        first_name: User's first name
        reset_url: Full URL of the set-password page
        expiry_hours: Hours until link expires (default 24)
    """
    portal_name = os.getenv('PORTAL_NAME', 'Blackfriars Network Portal')
    subject = f"Reset Your Password \u2013 {portal_name}"

    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(90deg,#2c7a7b,#3a9e9e); padding: 24px 28px; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 22px;">Reset Your Password</h1>
        </div>
        <div style="background: #f9f9f9; padding: 28px; border: 1px solid #dde2e8; border-top: none; border-radius: 0 0 8px 8px;">
            <p>Dear <strong>{first_name}</strong>,</p>
            <p>To reset your password for the {portal_name}, please click on the link below.</p>
            <p style="font-size: 13px; color: #888;">This link is valid for <strong>{expiry_hours} hours</strong>.</p>
            <div style="text-align: center; margin: 32px 0;">
                <a href="{reset_url}"
                   style="background: #2c7a7b; color: white; padding: 13px 30px; border-radius: 6px;
                          text-decoration: none; font-size: 15px; font-weight: bold;">
                    Reset My Password
                </a>
            </div>
            <p style="font-size: 13px; color: #666;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href="{reset_url}" style="color: #2c7a7b; word-break: break-all;">{reset_url}</a>
            </p>
            <hr style="border: none; border-top: 1px solid #dde2e8; margin: 24px 0;">
            <p style="font-size: 12px; color: #aaa; margin-top: 20px;">
                This is an automated message from {portal_name}
            </p>
        </div>
    </body></html>
    """

    text_body = f"""Reset Your Password \u2013 {portal_name}

Dear {first_name},

To reset your password for the {portal_name}, please click on the link below.

Reset your password here (valid for {expiry_hours} hours):
{reset_url}

---
This is an automated message from {portal_name}
"""

    return send_email(to_email, subject, html_body, text_body)
