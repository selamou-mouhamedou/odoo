#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script to install Chart of Accounts in Odoo 18
Usage: python install_chart_of_accounts.py
"""

import sys
import os

# Add Odoo to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'odoo'))

import odoo
from odoo import api, SUPERUSER_ID

def install_chart_of_accounts(db_name='odoo', chart_template_code='generic_coa'):
    """Install chart of accounts for a database"""
    
    # Initialize Odoo
    odoo.tools.config.parse_config(['-c', 'odoo.conf'])
    
    # Connect to database
    registry = odoo.registry(db_name)
    
    with registry.cursor() as cr:
        env = api.Environment(cr, SUPERUSER_ID, {})
        
        # Step 1: Check if accounting module is installed
        print("Step 1: Checking Accounting module...")
        account_module = env['ir.module.module'].search([('name', '=', 'account')], limit=1)
        
        if not account_module:
            print("❌ Accounting module not found!")
            print("Please install it through Apps menu first.")
            return False
        
        if account_module.state != 'installed':
            print(f"📦 Installing Accounting module (current state: {account_module.state})...")
            account_module.button_immediate_install()
            cr.commit()
            print("✅ Accounting module installed!")
            # Reset environment after module installation
            env = api.Environment(cr, SUPERUSER_ID, {})
        else:
            print("✅ Accounting module is already installed")
        
        # Step 2: Check if chart of accounts already exists
        print("\nStep 2: Checking for existing Chart of Accounts...")
        account_count = env['account.account'].search_count([
            ('account_type', 'in', ['income', 'income_other'])
        ])
        
        if account_count > 0:
            print(f"✅ Chart of Accounts already installed ({account_count} income accounts found)")
            return True
        
        # Step 3: Find and install chart template
        print(f"\nStep 3: Installing Chart of Accounts template: {chart_template_code}...")
        
        # Search for chart template
        chart_template = env['account.chart.template'].search([
            ('visible', '=', True),
        ], limit=1)
        
        # Try to find generic_coa specifically
        if chart_template_code == 'generic_coa':
            generic_template = env['account.chart.template'].search([
                ('visible', '=', True),
                ('name', 'ilike', 'generic'),
            ], limit=1)
            if generic_template:
                chart_template = generic_template
        
        if not chart_template:
            print("❌ No chart template found!")
            print("Available templates:")
            templates = env['account.chart.template'].search([('visible', '=', True)])
            for t in templates[:10]:  # Show first 10
                print(f"  - {t.name} (code: {getattr(t, 'code', 'N/A')})")
            return False
        
        print(f"📋 Found template: {chart_template.name}")
        
        # Get company
        company = env.company
        print(f"🏢 Installing for company: {company.name}")
        
        # Install chart template
        try:
            chart_template.try_loading(
                template_code=chart_template_code or None,
                company=company,
                install_demo=False
            )
            cr.commit()
            print("✅ Chart of Accounts installed successfully!")
            
            # Verify installation
            account_count = env['account.account'].search_count([
                ('account_type', 'in', ['income', 'income_other'])
            ])
            print(f"✅ Verification: {account_count} income accounts created")
            
            return True
            
        except Exception as e:
            print(f"❌ Error installing chart template: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Install Chart of Accounts in Odoo')
    parser.add_argument('-d', '--database', default='odoo', help='Database name')
    parser.add_argument('-t', '--template', default='generic_coa', help='Chart template code')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Odoo 18 - Chart of Accounts Installation Script")
    print("=" * 60)
    print()
    
    success = install_chart_of_accounts(args.database, args.template)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Installation completed successfully!")
        print("=" * 60)
        print("\nYou can now:")
        print("1. Go to Accounting > Configuration > Chart of Accounts")
        print("2. Create invoices from Smart Delivery")
        sys.exit(0)
    else:
        print("\n" + "=" * 60)
        print("❌ Installation failed. Please check the errors above.")
        print("=" * 60)
        sys.exit(1)
