# Step-by-Step: Install Chart of Accounts in Odoo 18

## Method 1: Through Odoo Web Interface (Recommended)

### Step 1: Install Accounting Module
1. Open your browser and go to: `http://localhost:8068`
2. Login with your admin credentials
3. Click on **Apps** menu (top left, or use the Apps icon)
4. In the search bar, type: **"Accounting"**
5. If it shows "Not Installed":
   - Click on the **"Accounting"** module card
   - Click the **"Install"** button
   - Wait for installation to complete (you'll see a progress indicator)

### Step 2: Install Chart of Accounts Template

**Option A: Through Setup Wizard (Easiest)**
1. After Accounting is installed, you might see a setup wizard automatically
2. If you see it:
   - Select a chart template (e.g., **"Generic Chart of Accounts"**)
   - Click **"Install"** or **"Continue"**
   - Wait for installation

**Option B: Manual Installation**
1. Go to **Accounting** app (should be in your apps menu now)
2. Navigate to: **Accounting** → **Configuration** → **Chart of Accounts**
3. You should see an empty list or a message
4. Look for the **"Favorites"** menu (star icon) in the search bar
5. Click on **"Favorites"** → Select **"Load a Chart of Accounts Template"**
6. A list of chart templates will appear
7. Select **"Generic Chart of Accounts"** (or your country-specific one)
8. Click **"Load"** or **"Install"**
9. Wait for the installation to complete

### Step 3: Verify Installation
1. Go to **Accounting** → **Configuration** → **Chart of Accounts**
2. You should now see a list of accounts
3. Filter or search for accounts with type **"Income"**
4. You should see accounts like:
   - Code: 400000 - Product Sales
   - Code: 410000 - Service Sales
   - Code: 420000 - Other Income
   - etc.

### Step 4: Test Invoice Creation
1. Go back to **Smart Delivery** → **Facturation**
2. Open any billing record
3. Click **"Créer Facture"** button
4. It should work now! ✅

---

## Method 2: Command Line Installation (Advanced)

If you prefer command line, you can use this script:

```bash
cd /Users/selamou/odoo/18.0
./venv/bin/python ./odoo/odoo-bin -c odoo.conf shell -d your_database_name
```

Then in the Python shell:
```python
# Install accounting module if not installed
account_module = env['ir.module.module'].search([('name', '=', 'account')])
if account_module.state != 'installed':
    account_module.button_immediate_install()
    env.cr.commit()

# Install generic chart of accounts
chart_template = env['account.chart.template'].search([
    ('visible', '=', True),
    ('name', 'ilike', 'generic')
], limit=1)

if chart_template:
    company = env.company
    chart_template.try_loading(company=company, install_demo=False)
    env.cr.commit()
    print("Chart of accounts installed successfully!")
else:
    print("Chart template not found")
```

---

## Method 3: Using the Helper Button (Easiest for Smart Delivery)

1. Go to **Smart Delivery** → **Facturation**
2. Open any billing record
3. Click the **"Installer Plan Comptable"** button in the header
4. Follow the on-screen instructions
5. The system will guide you through the installation

---

## Troubleshooting

### Issue: "Accounting module not found"
**Solution**: 
- Make sure you're using Odoo 18 (Community or Enterprise)
- Check if you have the `account` module in your addons path
- Try updating the apps list: **Apps** → **Update Apps List**

### Issue: "No chart templates available"
**Solution**:
- Make sure Accounting module is fully installed
- Try installing: **"l10n_generic_coa"** module (Generic Chart of Accounts)
- Go to **Apps** → Search **"Generic Chart"** → Install

### Issue: "Load template button not visible"
**Solution**:
1. Go to **Accounting** → **Configuration** → **Chart of Accounts**
2. Click the **search bar**
3. Look for the **"Favorites"** icon (star) in the search bar
4. Click it and select **"Load a Chart of Accounts Template"**

### Issue: Installation takes too long
**Solution**:
- This is normal, chart installation can take 1-2 minutes
- Don't close the browser
- Wait for the success message

---

## Quick Checklist

- [ ] Accounting module installed
- [ ] Chart of Accounts template loaded
- [ ] Income accounts visible in Chart of Accounts
- [ ] Can create invoice from Smart Delivery

---

## Common Chart Templates

- **Generic Chart of Accounts** - Works for most countries (Recommended to start)
- **US Chart of Accounts** - For United States
- **UK Chart of Accounts** - For United Kingdom  
- **France Chart of Accounts** - For France (Plan Comptable Général)
- **Canada Chart of Accounts** - For Canada
- And many more country-specific templates

**Recommendation**: Start with **"Generic Chart of Accounts"** - it works for most use cases.

---

## After Installation

Once installed, you should be able to:
- ✅ Create invoices from Smart Delivery
- ✅ See income accounts in Accounting → Configuration → Chart of Accounts
- ✅ Use all accounting features

---

## Need More Help?

If you're still having issues:
1. Check Odoo logs: `/Users/selamou/odoo/18.0/odoo.log`
2. Make sure Accounting module is installed: **Apps** → Search "Accounting"
3. Verify addons path includes accounting: Check `odoo.conf` file
