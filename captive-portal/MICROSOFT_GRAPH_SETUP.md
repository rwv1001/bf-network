# Microsoft Graph API Email Setup Guide

## Overview

This guide explains how to configure the captive portal to send emails using **Microsoft Graph API** instead of SMTP. This is the recommended approach for Microsoft 365/Outlook environments.

## Advantages Over SMTP

✅ **Better Security**: OAuth 2.0 authentication instead of username/password  
✅ **No Basic Auth**: Microsoft is deprecating basic authentication  
✅ **Better Reliability**: Enterprise-grade API with retry logic  
✅ **Audit Logging**: Full audit trail in Microsoft 365 admin center  
✅ **MFA Compatible**: Works with accounts that have MFA enabled  
✅ **Delegated Sending**: Send from shared mailbox or service account  

## Prerequisites

- Microsoft 365 account with admin access
- Azure Active Directory (included with Microsoft 365)
- Mailbox to send from (can be shared mailbox or user mailbox)

## Setup Steps

### Step 1: Register App in Azure AD

1. **Go to Azure Portal**: https://portal.azure.com
2. **Navigate to**: Azure Active Directory → App registrations
3. **Click**: "New registration"

**Registration details:**
- **Name**: `Captive Portal Email Service`
- **Supported account types**: "Accounts in this organizational directory only (Single tenant)"
- **Redirect URI**: Leave blank (not needed for service account)
- **Click**: "Register"

4. **Note down** the following from the Overview page:
   - **Application (client) ID**: This is your `GRAPH_CLIENT_ID`
   - **Directory (tenant) ID**: This is your `GRAPH_TENANT_ID`

### Step 2: Create Client Secret

1. **Navigate to**: Certificates & secrets (left sidebar)
2. **Click**: "New client secret"
3. **Description**: `Captive Portal Secret`
4. **Expires**: Choose expiration (recommend 24 months for production)
5. **Click**: "Add"
6. **Copy the secret VALUE immediately**: This is your `GRAPH_CLIENT_SECRET`
   - ⚠️ **Important**: You can only see this once! Save it securely.

### Step 3: Grant API Permissions

1. **Navigate to**: API permissions (left sidebar)
2. **Click**: "Add a permission"
3. **Select**: "Microsoft Graph"
4. **Select**: "Application permissions" (not Delegated)
5. **Find and add**: `Mail.Send`
6. **Click**: "Add permissions"
7. **Click**: "Grant admin consent for [Your Organization]"
8. **Confirm**: Click "Yes"

**Result**: You should see:
- `Mail.Send` - Application - Granted for [Your Organization]

### Step 4: Configure Sender Mailbox

You need to decide which mailbox will send the emails.

#### Option A: User Mailbox

Use an existing user account (e.g., `portaladmin@yourdomain.com`)

**Pros**: Simple setup  
**Cons**: Tied to a user account

#### Option B: Shared Mailbox (Recommended)

Create a dedicated shared mailbox for the portal:

1. **Go to**: Microsoft 365 admin center → Teams & groups → Shared mailboxes
2. **Click**: "Add a shared mailbox"
3. **Name**: `Network Portal`
4. **Email**: `portal@yourdomain.com`
5. **Click**: "Add"

**Pros**: Not tied to a user, better for automation  
**Cons**: Requires additional setup

**Note**: Shared mailboxes don't require a license!

### Step 5: Configure Environment Variables

Add these to `/home/admin/bf-network/captive-portal/.env`:

```bash
# Microsoft Graph API Configuration
GRAPH_TENANT_ID=your-tenant-id-here
GRAPH_CLIENT_ID=your-client-id-here
GRAPH_CLIENT_SECRET=your-client-secret-here
GRAPH_FROM_EMAIL=portal@yourdomain.com

# Admin email (receives registration requests)
ADMIN_EMAIL=admin@yourdomain.com

# Portal URL (for links in emails)
PORTAL_URL=https://portal.yourdomain.com

# Remove old SMTP settings (no longer needed)
# SMTP_HOST=...
# SMTP_PORT=...
# SMTP_USER=...
# SMTP_PASSWORD=...
```

### Step 6: Update Docker Container

```bash
cd /home/admin/bf-network/captive-portal

# Rebuild container with new dependencies
docker compose build web

# Restart services
docker compose down
docker compose up -d

# Check logs
docker logs -f captive-portal-web
```

### Step 7: Test Email Sending

```bash
# Test from within the container
docker exec -it captive-portal-web python3 << 'EOF'
from email_service import send_email

result = send_email(
    to_email='your-test-email@example.com',
    subject='Test Email from Captive Portal',
    html_body='<h1>Test</h1><p>If you receive this, Microsoft Graph is working!</p>',
    text_body='Test - If you receive this, Microsoft Graph is working!'
)

print(f"Email sent: {result}")
EOF
```

Check your inbox (and spam folder) for the test email.

## Troubleshooting

### Error: "Failed to acquire token"

**Cause**: Invalid credentials or app configuration

**Solutions**:
1. Verify `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET` are correct
2. Check client secret hasn't expired (Azure Portal → App registrations → Certificates & secrets)
3. Ensure no extra spaces in environment variables

### Error: "Forbidden" or "Access Denied"

**Cause**: Missing API permissions or admin consent

**Solutions**:
1. Go to Azure Portal → App registrations → API permissions
2. Verify `Mail.Send` (Application) permission is listed
3. Verify "Status" column shows "Granted for [Your Organization]"
4. If not, click "Grant admin consent for [Your Organization]"

### Error: "The specified object was not found in the store"

**Cause**: Sender email address doesn't exist or app doesn't have access

**Solutions**:
1. Verify `GRAPH_FROM_EMAIL` exists as a mailbox
2. For shared mailboxes: Ensure it's fully provisioned (can take 15 minutes)
3. Try using a regular user mailbox first to verify setup

### Error: "ErrorSendAsDenied"

**Cause**: App doesn't have permission to send as the specified mailbox

**Solutions**:

For **shared mailboxes**, grant Send As permission:
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Grant Send As permission
Add-RecipientPermission -Identity "portal@yourdomain.com" -Trustee "Captive Portal Email Service" -AccessRights SendAs

# Verify
Get-RecipientPermission -Identity "portal@yourdomain.com"
```

Or via Microsoft 365 admin center:
1. Teams & groups → Shared mailboxes
2. Select the mailbox → Members → Add members
3. Add the service principal (search by app name)

For **user mailboxes**, the `Mail.Send` application permission should be sufficient.

### Email Not Received

**Check**:
1. Spam/Junk folder
2. Portal container logs: `docker logs captive-portal-web`
3. Microsoft 365 Message Trace:
   - Go to: Exchange admin center → Mail flow → Message trace
   - Search for recipient email
   - Check delivery status

## Security Best Practices

### 1. Restrict App Permissions

The app only needs `Mail.Send` permission. Don't grant unnecessary permissions like:
- ❌ `Mail.ReadWrite` (can read all emails)
- ❌ `User.Read.All` (can read user data)
- ✅ `Mail.Send` (only send emails)

### 2. Rotate Client Secrets

Set a calendar reminder to rotate secrets before expiration:

```bash
# When rotating:
# 1. Create new secret in Azure Portal
# 2. Update GRAPH_CLIENT_SECRET in .env
# 3. Restart container: docker compose restart web
# 4. Test email sending
# 5. Delete old secret from Azure Portal
```

### 3. Use Managed Identity (Azure Only)

If running on Azure VM/App Service, use managed identity instead of client secret:

```python
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
token = credential.get_token("https://graph.microsoft.com/.default")
```

### 4. Monitor API Usage

Check API call volume:
- Azure Portal → Azure Active Directory → App registrations → Your app
- Monitor sign-ins and token requests

Microsoft Graph has rate limits:
- 10,000 requests per 10 minutes per app per tenant
- Should be more than sufficient for a captive portal

## Advanced Configuration

### Send from Different Addresses Based on Context

Modify `email_service.py`:

```python
def send_email(to_email, subject, html_body, text_body=None, from_email=None):
    # Use custom sender or fall back to default
    sender = from_email or GRAPH_FROM_EMAIL
    
    # Update email message
    send_url = f"{GRAPH_ENDPOINT}/users/{sender}/sendMail"
    # ... rest of code
```

### Add Email Attachments

```python
# In email_message dict:
"attachments": [
    {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": "network-policy.pdf",
        "contentType": "application/pdf",
        "contentBytes": base64_encoded_content
    }
]
```

### Add CC/BCC Recipients

```python
# In email_message dict:
"ccRecipients": [
    {"emailAddress": {"address": "cc@example.com"}}
],
"bccRecipients": [
    {"emailAddress": {"address": "bcc@example.com"}}
]
```

### Use Email Templates with Variables

Store templates in database `settings` table:

```python
# Template with placeholders
template = Setting.get_value('email_template_registration')
html_body = template.format(
    first_name=first_name,
    ssid=ssid,
    unregister_url=unregister_url
)
```

## Monitoring & Logging

### Portal Logs

```bash
# Watch email sending in real-time
docker logs -f captive-portal-web | grep "Email sent"

# Check for errors
docker logs captive-portal-web | grep -i "error.*email"
```

### Microsoft 365 Audit Logs

1. Go to: Microsoft 365 Defender → Audit
2. Search for: Activity = "Send message"
3. Filter by: User = portal@yourdomain.com

### Set Up Alerts

Create alert for failed email sending:

```python
# In email_service.py, after failed send:
if not response.ok:
    # Send alert to admin via different channel
    # e.g., Teams webhook, Slack, PagerDuty
    send_alert(f"Email service failed: {response.text}")
```

## Migration from SMTP

If you have existing SMTP configuration:

```bash
# 1. Backup .env
cp captive-portal/.env captive-portal/.env.backup

# 2. Add Graph settings (keep SMTP for now)
cat >> captive-portal/.env << 'EOF'

# Microsoft Graph API (new)
GRAPH_TENANT_ID=...
GRAPH_CLIENT_ID=...
GRAPH_CLIENT_SECRET=...
GRAPH_FROM_EMAIL=...
EOF

# 3. Test Graph API
docker exec -it captive-portal-web python3 -c "from email_service import send_email; send_email('test@example.com', 'Test', '<p>Test</p>')"

# 4. Once working, remove SMTP settings from .env
# Comment out or delete:
# SMTP_HOST=...
# SMTP_PORT=...
# SMTP_USER=...
# SMTP_PASSWORD=...

# 5. Rebuild and restart
cd captive-portal
docker compose build web
docker compose restart
```

## Cost Considerations

**Microsoft Graph API is included with Microsoft 365** - no additional cost!

- ✅ No per-email charges
- ✅ No API call charges (within reasonable limits)
- ✅ Shared mailboxes are free (no license required)

Compare to SMTP:
- Some providers charge per email
- Basic auth being deprecated
- Less reliable delivery

## Reference Links

- **Microsoft Graph API Documentation**: https://learn.microsoft.com/graph/api/user-sendmail
- **App Registration Guide**: https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app
- **Mail.Send Permission**: https://learn.microsoft.com/graph/permissions-reference#mailsend
- **Shared Mailboxes**: https://learn.microsoft.com/microsoft-365/admin/email/create-a-shared-mailbox

## Support

If you encounter issues:

1. **Check logs**: `docker logs captive-portal-web`
2. **Verify credentials**: Azure Portal → App registrations
3. **Test API directly**: Use Graph Explorer (https://developer.microsoft.com/graph/graph-explorer)
4. **Check permissions**: Ensure admin consent granted
5. **Review audit logs**: Microsoft 365 Defender → Audit

## Summary

Microsoft Graph provides a modern, secure, and reliable way to send emails from the captive portal:

- ✅ **Setup time**: ~15 minutes
- ✅ **Security**: OAuth 2.0, no password storage
- ✅ **Reliability**: Enterprise-grade API
- ✅ **Cost**: Included with Microsoft 365
- ✅ **Future-proof**: Microsoft's recommended approach

You're now ready to send emails via Microsoft Graph! 📧
