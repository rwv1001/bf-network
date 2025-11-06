# Logo Installation Instructions

To complete the branding setup, you need to add the logo file:

1. Download or copy the logo file: `laurare-2827310_960_720.png`

2. Place it in: `/home/admin/bf-network/captive-portal/app/static/laurare-2827310_960_720.png`

For example:
```bash
# If you have the logo file locally:
cp /path/to/laurare-2827310_960_720.png /home/admin/bf-network/captive-portal/app/static/

# Or download it:
cd /home/admin/bf-network/captive-portal/app/static/
wget https://your-url/laurare-2827310_960_720.png
```

3. Restart the captive portal:
```bash
cd /home/admin/bf-network/captive-portal
docker compose restart web
```

The portal will now display the Blackfriars logo with the red/gray/black color scheme.

If you don't have the logo yet, you can temporarily use a placeholder or skip this step and the page will still work (just without the logo image).
