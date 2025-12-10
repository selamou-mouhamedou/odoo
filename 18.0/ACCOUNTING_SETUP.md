# Step-by-Step Guide: Install Accounting Module and Chart of Accounts

## Step 1: Access Odoo Web Interface

1. Open your browser
2. Go to: `http://localhost:8068` (or your Odoo URL)
3. Login with your admin credentials

## Step 2: Install Accounting Module

1. Click on the **Apps** menu (top left, or use the Apps icon)
2. In the search bar, type: **"Accounting"**
3. Find the **"Accounting"** module (should show as "Installed" or "Not Installed")
4. If it shows "Not Installed":
   - Click on the **"Accounting"** module card
   - Click the **"Install"** button
   - Wait for the installation to complete

## Step 3: Install Chart of Accounts

After Accounting is installed, you need to install a chart of accounts:

### Option A: Through the Accounting App (Recommended)

1. Go to **Accounting** app (should be in your apps menu now)
2. If you see a setup wizard, follow it:
   - It will ask you to select a chart of accounts template
   - Choose your country (e.g., "Generic Chart of Accounts" or your country-specific one)
   - Click **"Install"** or **"Continue"**

### Option B: Manual Installation

1. Go to **Accounting** → **Configuration** → **Chart of Accounts**
2. If you see an empty list, click **"Load a Chart of Accounts Template"**
3. Select a template (e.g., "Generic Chart of Accounts")
4. Click **"Load"** or **"Install"**

### Option C: Through Apps Menu

1. Go to **Apps** menu
2. Search for **"Chart of Accounts"** or **"Account Charts"**
3. Install the chart template for your country/region

## Step 4: Verify Installation

1. Go to **Accounting** → **Configuration** → **Chart of Accounts**
2. You should see a list of accounts
3. Look for accounts with type **"Income"** (they should have codes like 4000, 4100, etc.)

## Step 5: Test Invoice Creation

After the chart of accounts is installed, try creating an invoice again from your Smart Delivery billing module. It should work now!

## Troubleshooting

### If Accounting module is not available:

1. Check if you're using Odoo Community (Accounting might be limited)
2. If using Enterprise, make sure enterprise addons are properly loaded
3. Try updating the module list:
   - Go to **Apps** → Click **"Update Apps List"** (top right)

### If Chart of Accounts installation fails:

1. Make sure Accounting module is fully installed
2. Try installing a generic chart first: **"Generic Chart of Accounts"**
3. Check Odoo logs for errors: `/Users/selamou/odoo/18.0/odoo.log`

### Quick Command Line Check

You can also check if accounting is installed via command line:

```bash
cd /Users/selamou/odoo/18.0
./venv/bin/python ./odoo/odoo-bin -c odoo.conf shell -d your_database_name
```

Then in the shell:
```python
env['ir.module.module'].search([('name', '=', 'account')]).state
```

## Common Chart of Accounts Templates

- **Generic Chart of Accounts** - Works for most countries
- **US Chart of Accounts** - For United States
- **UK Chart of Accounts** - For United Kingdom
- **France Chart of Accounts** - For France (Plan Comptable Général)
- And many more country-specific templates

## After Installation

Once the chart of accounts is installed, your Smart Delivery invoice creation should work without errors!
