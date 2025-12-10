# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError


class DeliveryBilling(models.Model):
    _name = 'delivery.billing'
    _description = 'Facturation de Livraison'

    order_id = fields.Many2one('delivery.order', string='Commande', required=True, ondelete='cascade')
    
    @api.model
    def default_get(self, fields_list):
        """Override to safely handle default_order_id from context"""
        res = super().default_get(fields_list)
        # Safely get default_order_id from context, handling cases where active_id might not be available
        if 'order_id' in fields_list and 'default_order_id' not in res:
            # Try to get from context, but handle if active_id is not defined
            ctx = self.env.context
            if 'default_order_id' in ctx:
                res['order_id'] = ctx.get('default_order_id')
            elif 'active_id' in ctx and ctx.get('active_model') == 'delivery.order':
                res['order_id'] = ctx.get('active_id')
            elif 'active_ids' in ctx and ctx.get('active_model') == 'delivery.order' and ctx.get('active_ids'):
                res['order_id'] = ctx.get('active_ids')[0]
        return res
    
    distance_km = fields.Float(string='Distance (km)', digits=(10, 2))
    base_tariff = fields.Float(string='Tarif de Base', digits=(10, 2))
    extra_fee = fields.Float(string='Frais Supplémentaires', digits=(10, 2), default=0.0)
    total_amount = fields.Float(string='Montant Total', digits=(10, 2), required=True)
    commission = fields.Float(string='Commission', digits=(10, 2))
    
    invoice_id = fields.Many2one(
        'account.move', 
        string='Facture', 
        readonly=True,
        check_company=True,
    )
    invoice_state = fields.Selection(
        related='invoice_id.state', 
        string='État Facture', 
        readonly=True, 
        store=False
    )
    
    has_account_module = fields.Boolean(
        string='Has Account Module',
        compute='_compute_has_account_module',
        default=False,
    )
    
    @api.depends()
    def _compute_has_account_module(self):
        """Check if account module is installed"""
        for record in self:
            record.has_account_module = 'account.move' in self.env
    
    def _is_account_module_installed(self):
        """Check if account module is installed"""
        return 'account.move' in self.env
    
    def _get_or_create_sale_journal(self):
        """Get or create a sales journal for invoicing"""
        company = self.env.company
        journal = self.env['account.journal'].search([
            ('type', '=', 'sale'),
            ('company_id', '=', company.id),
        ], limit=1)
        
        if not journal:
            # Create a sales journal if none exists
            journal = self.env['account.journal'].create({
                'name': _('Customer Invoices'),
                'code': 'INV',
                'type': 'sale',
                'company_id': company.id,
            })
        
        return journal
    
    def _get_income_account(self, journal):
        """Get or create an income account for invoice lines compatible with the journal"""
        company = self.env.company
        
        # First, try to use the journal's default income account
        if hasattr(journal, 'default_account_id') and journal.default_account_id:
            if journal.default_account_id.account_type in ['income', 'income_other']:
                return journal.default_account_id
        
        # Try to find an account from the journal's company
        # In Odoo 18, accounts might be linked via company_ids or other means
        # Search for active income accounts
        account = self.env['account.account'].search([
            ('account_type', '=', 'income'),
            ('deprecated', '=', False),
        ], limit=1, order='id')
        
        if not account:
            # Try income_other type
            account = self.env['account.account'].search([
                ('account_type', '=', 'income_other'),
                ('deprecated', '=', False),
            ], limit=1, order='id')
        
        if not account:
            # Try to find any revenue-type account (without deprecated filter as fallback)
            account = self.env['account.account'].search([
                ('account_type', 'in', ['income', 'income_other']),
            ], limit=1, order='id')
        
        if not account or not account.id:
            # Provide helpful error with action to install chart of accounts
            action = {
                'name': _('Install Chart of Accounts'),
                'type': 'ir.actions.act_window',
                'res_model': 'account.chart.template',
                'view_mode': 'list,form',
                'target': 'current',
                'context': {'search_default_visible': True},
            }
            raise UserError(_(
                'No income account found. Please install a Chart of Accounts first.\n\n'
                'Steps to fix:\n'
                '1. Go to Apps menu\n'
                '2. Search for "Accounting" and install it if not installed\n'
                '3. Go to Accounting > Configuration > Chart of Accounts\n'
                '4. Click "Load a Chart of Accounts Template"\n'
                '5. Select "Generic Chart of Accounts" (or your country-specific one)\n'
                '6. Click "Load" to install\n\n'
                'After installation, try creating the invoice again.'
            ))
        
        return account
    
    def action_install_chart_of_accounts(self):
        """Helper action to guide user to install chart of accounts"""
        self.ensure_one()
        
        # Check if accounting module is installed
        if not self._is_account_module_installed():
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Accounting Module Required'),
                    'message': _(
                        'Please install the Accounting module first:\n\n'
                        '1. Go to Apps menu (top left)\n'
                        '2. Search for "Accounting"\n'
                        '3. Click "Install" button\n'
                        '4. Wait for installation to complete\n\n'
                        'Then come back and click this button again.'
                    ),
                    'type': 'warning',
                    'sticky': True,
                }
            }
        
        # Check if chart of accounts exists
        account_count = self.env['account.account'].search_count([('account_type', 'in', ['income', 'income_other'])])
        if account_count == 0:
            # Try to open chart of accounts configuration
            try:
                # Try to open the chart of accounts view with action to load template
                return {
                    'type': 'ir.actions.act_window',
                    'name': _('Chart of Accounts'),
                    'res_model': 'account.account',
                    'view_mode': 'list',
                    'target': 'current',
                    'context': {
                        'search_default_account_type': 'income',
                        'create': False,
                    },
                    'help': _(
                        'No income accounts found. To install a Chart of Accounts:\n\n'
                        '1. Click the "Favorites" menu (star icon) in the search bar\n'
                        '2. Select "Load a Chart of Accounts Template"\n'
                        '3. Choose "Generic Chart of Accounts" (or your country-specific one)\n'
                        '4. Click "Load" to install\n\n'
                        'After installation, return here and try creating the invoice again.'
                    ),
                }
            except Exception as e:
                _logger.error(f"Error opening chart of accounts: {e}")
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Install Chart of Accounts'),
                        'message': _(
                            'To install a Chart of Accounts:\n\n'
                            '1. Go to: Accounting > Configuration > Chart of Accounts\n'
                            '2. Click "Load a Chart of Accounts Template" (in Favorites menu)\n'
                            '3. Select "Generic Chart of Accounts"\n'
                            '4. Click "Load"\n\n'
                            'Then try creating the invoice again.'
                        ),
                        'type': 'info',
                        'sticky': True,
                    }
                }
        
        # If accounts exist, show them
        return {
            'type': 'ir.actions.act_window',
            'name': _('Income Accounts'),
            'res_model': 'account.account',
            'view_mode': 'list,form',
            'domain': [('account_type', 'in', ['income', 'income_other'])],
        }
    
    def action_create_invoice(self):
        """Crée une facture pour cette facturation"""
        self.ensure_one()
        
        # Check if account module is installed
        if not self._is_account_module_installed():
            raise UserError(_(
                'The Accounting module is not installed. '
                'Please install the Accounting module to create invoices. '
                'Go to Apps and install the "Accounting" module.'
            ))
        
        if self.invoice_id:
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'account.move',
                'res_id': self.invoice_id.id,
                'view_mode': 'form',
            }
        
        # Check if chart of accounts is installed
        account_count = self.env['account.account'].search_count([('account_type', 'in', ['income', 'income_other'])])
        if account_count == 0:
            # Provide action to install chart of accounts
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Chart of Accounts Required'),
                    'message': _(
                        'No income accounts found. Please install a Chart of Accounts first.\n\n'
                        'Steps:\n'
                        '1. Go to Accounting > Configuration > Chart of Accounts\n'
                        '2. Click "Load a Chart of Accounts Template"\n'
                        '3. Select "Generic Chart of Accounts"\n'
                        '4. Click "Load"\n\n'
                        'Then try creating the invoice again.'
                    ),
                    'type': 'warning',
                    'sticky': True,
                }
            }
        
        # Ensure we have a sales journal and income account
        journal = self._get_or_create_sale_journal()
        income_account = self._get_income_account(journal)
        
        if not income_account or not income_account.id:
            raise UserError(_('Could not find a valid income account. Please configure your chart of accounts.'))
        
        # Verify account is valid for invoice lines
        if income_account.account_type not in ['income', 'income_other']:
            raise UserError(_('The selected account is not an income account. Please configure a proper income account.'))
        
        # Create invoice line with all required fields
        line_vals = {
            'name': f'Livraison {self.order_id.name}',
            'quantity': 1,
            'price_unit': self.total_amount,
            'account_id': income_account.id,
        }
        
        # Create invoice with line
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.order_id.sender_id.id,
            'journal_id': journal.id,
            'invoice_line_ids': [(0, 0, line_vals)],
        })
        
        self.write({'invoice_id': invoice.id})
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'account.move',
            'res_id': invoice.id,
            'view_mode': 'form',
        }
    
    def action_view_invoice(self):
        """View the associated invoice"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('No invoice associated with this billing.'))
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'account.move',
            'res_id': self.invoice_id.id,
            'view_mode': 'form',
        }

