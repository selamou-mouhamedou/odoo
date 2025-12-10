# Switching from Odoo Community to Enterprise Edition

## Prerequisites

⚠️ **Important**: Odoo Enterprise Edition requires:
- An active Odoo Enterprise subscription/license
- Access to the Odoo Enterprise repository (private GitHub repository)
- Your Odoo.com account credentials

## Step 1: Get Access to Enterprise Addons

You need to:
1. Have an active Odoo Enterprise subscription
2. Get access to the Enterprise repository from Odoo
3. Clone the repository using your Odoo.com credentials

## Step 2: Clone Enterprise Addons

```bash
cd /Users/selamou/odoo/18.0

# Clone enterprise addons (replace with your actual repository URL)
# You'll get this URL from your Odoo account
git clone https://github.com/odoo/enterprise.git --branch 18.0 --depth 1 enterprise
```

**Note**: The actual repository URL is private and provided by Odoo when you have a subscription.

## Step 3: Update Odoo Configuration

Update your `odoo.conf` file to include the enterprise addons path:

```ini
[options]
addons_path = /Users/selamou/odoo/18.0/odoo/addons,/Users/selamou/odoo/18.0/enterprise,/Users/selamou/odoo/18.0/custom-addons
db_host = localhost
db_port = 5432
db_user = odoo
db_password = 010203
logfile = /Users/selamou/odoo/18.0/odoo.log
admin_passwd = $pbkdf2-sha512$600000$eo8xhlBqbU0JASDknBNizA$JlDJHeCfRIYkEz5NCB48.IcaX8vqnPa70BVmovxebYwGvISpzywxBoxeZUyYUc968hGKD.nG87oAiF6HjmYkyQ
xmlrpc_port = 8069
```

## Step 4: Update Database

After adding enterprise addons, you need to update your database:

```bash
cd /Users/selamou/odoo/18.0
./venv/bin/python ./odoo/odoo-bin -c odoo.conf -u all -d your_database_name --stop-after-init
```

## Step 5: Install Enterprise Apps

1. Go to Odoo web interface
2. Navigate to Apps menu
3. Remove "Apps" filter to see all apps
4. Install enterprise modules you need (e.g., `account_accountant`, `sale_enterprise`, etc.)

## Alternative: Using Odoo.sh or SaaS

If you're using Odoo.sh or Odoo SaaS:
- Enterprise is already included
- No need to download addons manually
- Just activate your subscription in the Odoo interface

## Troubleshooting

### If you don't have Enterprise subscription:
- Contact Odoo sales: https://www.odoo.com/trial
- Or use Odoo Community Edition (which you currently have)

### If repository access is denied:
- Verify your GitHub account is linked to your Odoo.com account
- Check your subscription status in Odoo.com
- Contact Odoo support

### If modules don't appear:
- Check addons_path in odoo.conf
- Restart Odoo server
- Update apps list: `-u base` then restart

## Current Configuration

Your current `addons_path`:
```
/Users/selamou/odoo/18.0/odoo/addons,/Users/selamou/odoo/18.0/custom-addons
```

After adding Enterprise, it should be:
```
/Users/selamou/odoo/18.0/odoo/addons,/Users/selamou/odoo/18.0/enterprise,/Users/selamou/odoo/18.0/custom-addons
```
