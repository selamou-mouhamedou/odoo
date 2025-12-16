# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)


class DeliveryBilling(models.Model):
    _name = 'delivery.billing'
    _description = 'Facturation de Livraison'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    _rec_name = 'display_name'

    # ==================== CORE FIELDS ====================
    order_id = fields.Many2one(
        'delivery.order',
        string='Commande',
        required=True,
        ondelete='cascade',
        index=True,
        tracking=True,
    )
    
    display_name = fields.Char(compute='_compute_display_name', store=True)
    
    @api.depends('order_id', 'invoice_id')
    def _compute_display_name(self):
        for record in self:
            if record.invoice_id:
                record.display_name = f"{record.order_id.name} - {record.invoice_id.name}"
            else:
                record.display_name = f"{record.order_id.name} - Brouillon"

    # ==================== PRICING FIELDS ====================
    distance_km = fields.Float(string='Distance (km)', digits=(10, 2), tracking=True)
    base_tariff = fields.Float(string='Tarif de Base (MRU)', digits=(10, 2), tracking=True)
    extra_fee = fields.Float(string='Frais de Distance (MRU)', digits=(10, 2), default=0.0, tracking=True)
    total_amount = fields.Float(
        string='Montant Total (MRU)',
        digits=(10, 2),
        compute='_compute_total_amount',
        store=True,
        tracking=True,
    )
    currency_id = fields.Many2one(
        'res.currency',
        string='Devise',
        default=lambda self: self.env.company.currency_id,
        readonly=True,
    )
    
    @api.depends('base_tariff', 'extra_fee')
    def _compute_total_amount(self):
        for record in self:
            record.total_amount = record.base_tariff + record.extra_fee

    # ==================== ENTERPRISE / PARTNER INFO ====================
    enterprise_id = fields.Many2one(
        'delivery.enterprise',
        string='Entreprise Expéditrice',
        compute='_compute_enterprise_id',
        store=True,
    )
    
    sender_partner_id = fields.Many2one(
        'res.partner',
        string='Expéditeur',
        related='order_id.sender_id',
        store=True,
    )
    
    receiver_partner_id = fields.Many2one(
        'res.partner',
        string='Destinataire (Payeur)',
        compute='_compute_receiver_partner',
        store=True,
    )
    
    @api.depends('order_id.sender_id')
    def _compute_enterprise_id(self):
        for record in self:
            if record.order_id and record.order_id.sender_id:
                enterprise = self.env['delivery.enterprise'].search([
                    ('partner_id', '=', record.order_id.sender_id.id)
                ], limit=1)
                record.enterprise_id = enterprise.id if enterprise else False
            else:
                record.enterprise_id = False
    
    @api.depends('order_id.receiver_phone', 'order_id.receiver_name')
    def _compute_receiver_partner(self):
        """Get or create partner for receiver (the one who pays - COD)"""
        for record in self:
            if not record.order_id:
                record.receiver_partner_id = False
                continue
            
            phone = record.order_id.receiver_phone
            if not phone:
                record.receiver_partner_id = False
                continue
            
            # Search for existing partner
            partner = self.env['res.partner'].search([('phone', '=', phone)], limit=1)
            if not partner:
                # Create new partner for receiver
                partner = self.env['res.partner'].create({
                    'name': record.order_id.receiver_name or phone,
                    'phone': phone,
                    'customer_rank': 1,
                })
            record.receiver_partner_id = partner.id

    # ==================== INVOICE INTEGRATION (ODOO ACCOUNTING) ====================
    invoice_id = fields.Many2one(
        'account.move',
        string='Facture Client',
        readonly=True,
        copy=False,
        tracking=True,
        domain="[('move_type', '=', 'out_invoice')]",
    )
    
    # Related invoice fields for easy access
    invoice_name = fields.Char(related='invoice_id.name', string='N° Facture')
    invoice_state = fields.Selection(related='invoice_id.state', string='État Facture', store=True)
    invoice_payment_state = fields.Selection(
        related='invoice_id.payment_state',
        string='État Paiement',
        store=True,
    )
    invoice_amount_residual = fields.Monetary(
        related='invoice_id.amount_residual',
        string='Reste à Payer',
        currency_field='currency_id',
    )
    invoice_amount_total = fields.Monetary(
        related='invoice_id.amount_total',
        string='Montant Facture',
        currency_field='currency_id',
    )
    
    # ==================== STATE MANAGEMENT ====================
    state = fields.Selection([
        ('draft', 'Brouillon'),
        ('invoiced', 'Facturé'),
        ('posted', 'Confirmé'),
        ('partial', 'Partiellement Payé'),
        ('paid', 'Payé'),
        ('cancelled', 'Annulé'),
    ], string='État', default='draft', compute='_compute_state', store=True, tracking=True)
    
    @api.depends('invoice_id', 'invoice_id.state', 'invoice_id.payment_state')
    def _compute_state(self):
        """State is fully driven by the linked invoice"""
        for record in self:
            if not record.invoice_id:
                record.state = 'draft'
            elif record.invoice_id.state == 'cancel':
                record.state = 'cancelled'
            elif record.invoice_id.state == 'draft':
                record.state = 'invoiced'
            elif record.invoice_id.state == 'posted':
                if record.invoice_id.payment_state == 'paid':
                    record.state = 'paid'
                elif record.invoice_id.payment_state == 'partial':
                    record.state = 'partial'
                elif record.invoice_id.payment_state in ('in_payment', 'not_paid'):
                    record.state = 'posted'
                else:
                    record.state = 'posted'

    notes = fields.Text(string='Notes Internes')
    
    # ==================== COMPUTED FIELDS FOR UI ====================
    payment_count = fields.Integer(compute='_compute_payment_count', string='Paiements')
    
    def _compute_payment_count(self):
        for record in self:
            if record.invoice_id:
                # Get payments linked to this invoice
                payments = self.env['account.payment'].search([
                    ('reconciled_invoice_ids', 'in', record.invoice_id.id)
                ])
                record.payment_count = len(payments)
            else:
                record.payment_count = 0

    # ==================== MODEL METHODS ====================
    
    @api.model
    def default_get(self, fields_list):
        """Handle default values from context"""
        res = super().default_get(fields_list)
        ctx = self.env.context
        if 'order_id' in fields_list and 'order_id' not in res:
            if ctx.get('default_order_id'):
                res['order_id'] = ctx['default_order_id']
            elif ctx.get('active_model') == 'delivery.order' and ctx.get('active_id'):
                res['order_id'] = ctx['active_id']
        return res

    @api.model_create_multi
    def create(self, vals_list):
        """Auto-create invoice on billing creation if configured"""
        records = super().create(vals_list)
        # Optionally auto-create invoice - controlled by context
        if self.env.context.get('auto_create_invoice', False):
            for record in records:
                if not record.invoice_id:
                    record.action_create_invoice()
        return records

    def _get_sector_rule(self):
        """Get sector rule for the order"""
        self.ensure_one()
        return self.env['sector.rule'].search([
            ('sector_type', '=', self.order_id.sector_type)
        ], limit=1)

    def _get_delivery_product(self):
        """Get appropriate delivery product based on sector type"""
        self.ensure_one()
        product_mapping = {
            'standard': 'smart_delivery.product_delivery_standard',
            'premium': 'smart_delivery.product_delivery_premium',
            'express': 'smart_delivery.product_delivery_express',
            'fragile': 'smart_delivery.product_delivery_fragile',
            'medical': 'smart_delivery.product_delivery_medical',
        }
        xml_id = product_mapping.get(self.order_id.sector_type, 'smart_delivery.product_delivery_standard')
        return self.env.ref(xml_id, raise_if_not_found=False) or \
               self.env.ref('smart_delivery.product_delivery_service', raise_if_not_found=False)

    def _get_distance_product(self):
        """Get distance fee product"""
        return self.env.ref('smart_delivery.product_distance_fee', raise_if_not_found=False)

    def _prepare_invoice_line_vals(self):
        """Prepare invoice line values"""
        self.ensure_one()
        lines = []
        
        sector_rule = self._get_sector_rule()
        delivery_product = self._get_delivery_product()
        distance_product = self._get_distance_product()
        
        sector_labels = {
            'standard': 'Standard',
            'premium': 'Premium',
            'express': 'Express',
            'fragile': 'Fragile',
            'medical': 'Médical',
        }
        sector_label = sector_labels.get(self.order_id.sector_type, 'Standard')
        
        # Line 1: Base delivery service
        line1 = {
            'name': f"Service de Livraison {sector_label} - {self.order_id.name}",
            'quantity': 1,
            'price_unit': self.base_tariff,
        }
        if delivery_product:
            line1['product_id'] = delivery_product.id
        lines.append((0, 0, line1))
        
        # Line 2: Distance fee if applicable
        if self.extra_fee > 0:
            free_distance = sector_rule.free_distance_km if sector_rule else 5.0
            extra_km = max(0, self.distance_km - free_distance)
            line2 = {
                'name': f"Frais de distance ({extra_km:.1f} km supplémentaires)",
                'quantity': extra_km,
                'price_unit': sector_rule.distance_fee_per_km if sector_rule else 10.0,
            }
            if distance_product:
                line2['product_id'] = distance_product.id
            lines.append((0, 0, line2))
        
        return lines

    def _prepare_invoice_vals(self):
        """Prepare invoice values for Odoo accounting"""
        self.ensure_one()
        
        if not self.receiver_partner_id:
            raise UserError(_('Aucun destinataire défini. Vérifiez les informations de la commande.'))
        
        # Get sale journal
        journal = self.env['account.journal'].search([
            ('type', '=', 'sale'),
            ('company_id', '=', self.env.company.id),
        ], limit=1)
        
        if not journal:
            raise UserError(_('Aucun journal de vente trouvé. Configurez la comptabilité.'))
        
        enterprise_name = self.enterprise_id.name if self.enterprise_id else 'Smart Delivery'
        
        return {
            'move_type': 'out_invoice',
            'partner_id': self.receiver_partner_id.id,
            'journal_id': journal.id,
            'invoice_date': fields.Date.today(),
            'invoice_origin': self.order_id.name,
            'ref': f"{enterprise_name} - {self.order_id.name}",
            'narration': f"""Facture de livraison
Entreprise: {enterprise_name}
Commande: {self.order_id.name}
Type: {self.order_id.sector_type}
Distance: {self.distance_km:.2f} km
Mode de paiement: Espèces à la livraison (COD)
{self.notes or ''}""",
            'invoice_line_ids': self._prepare_invoice_line_vals(),
        }

    # ==================== ACTION METHODS ====================
    
    def action_create_invoice(self):
        """Create Odoo invoice from billing record"""
        self.ensure_one()
        
        if self.invoice_id:
            raise UserError(_('Une facture existe déjà pour cette facturation.'))
        
        if self.state == 'cancelled':
            raise UserError(_('Impossible de créer une facture pour une facturation annulée.'))
        
        # Create invoice using Odoo's standard method
        invoice_vals = self._prepare_invoice_vals()
        invoice = self.env['account.move'].create(invoice_vals)
        self.invoice_id = invoice.id
        
        self.message_post(body=_('Facture %s créée') % invoice.name)
        
        # Return action to view invoice in accounting
        return self._action_view_invoice()
    
    def action_post_invoice(self):
        """Confirm/Post the invoice"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture à confirmer. Créez d\'abord une facture.'))
        
        if self.invoice_id.state == 'draft':
            self.invoice_id.action_post()
            self.message_post(body=_('Facture %s confirmée') % self.invoice_id.name)
        
        return True
    
    def action_register_payment(self):
        """Open Odoo's standard payment registration wizard"""
        self.ensure_one()
        
        if not self.invoice_id:
            raise UserError(_('Créez d\'abord une facture.'))
        
        if self.invoice_id.state != 'posted':
            raise UserError(_('Confirmez d\'abord la facture avant d\'enregistrer un paiement.'))
        
        if self.invoice_id.payment_state == 'paid':
            raise UserError(_('Cette facture est déjà payée.'))
        
        # Use Odoo's standard payment register wizard
        return {
            'name': _('Enregistrer un Paiement'),
            'type': 'ir.actions.act_window',
            'res_model': 'account.payment.register',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'active_model': 'account.move',
                'active_ids': [self.invoice_id.id],
                'active_id': self.invoice_id.id,
                'default_payment_type': 'inbound',
                'default_partner_type': 'customer',
            },
        }
    
    def action_quick_pay_cash(self):
        """Quick cash payment - creates payment with journal entry and reconciles automatically"""
        self.ensure_one()
        
        if not self.invoice_id:
            # Create invoice first
            self.action_create_invoice()
        
        if self.invoice_id.state == 'draft':
            self.invoice_id.action_post()
        
        if self.invoice_id.payment_state == 'paid':
            return {'type': 'ir.actions.act_window_close'}
        
        # Find cash journal
        cash_journal = self.env['account.journal'].search([
            ('type', '=', 'cash'),
            ('company_id', '=', self.env.company.id),
        ], limit=1)
        
        if not cash_journal:
            cash_journal = self.env['account.journal'].search([
                ('type', '=', 'bank'),
                ('company_id', '=', self.env.company.id),
            ], limit=1)
        
        if not cash_journal:
            raise UserError(_('Aucun journal de caisse ou banque trouvé.'))
        
        # Get the receivable account from the invoice
        invoice_receivable_line = self.invoice_id.line_ids.filtered(
            lambda l: l.account_id.account_type == 'asset_receivable'
        )
        
        if not invoice_receivable_line:
            raise UserError(_('Aucun compte client trouvé sur la facture.'))
        
        receivable_account = invoice_receivable_line[0].account_id
        
        # Create the payment journal entry directly
        move_vals = {
            'move_type': 'entry',
            'journal_id': cash_journal.id,
            'date': fields.Date.today(),
            'ref': f"Paiement {self.invoice_id.name}",
            'line_ids': [
                # Debit: Cash account (increases cash)
                (0, 0, {
                    'account_id': cash_journal.default_account_id.id,
                    'partner_id': self.invoice_id.partner_id.id,
                    'name': f"Paiement client - {self.invoice_id.name}",
                    'debit': self.invoice_id.amount_residual,
                    'credit': 0,
                }),
                # Credit: Receivable account (decreases receivable)
                (0, 0, {
                    'account_id': receivable_account.id,
                    'partner_id': self.invoice_id.partner_id.id,
                    'name': f"Paiement client - {self.invoice_id.name}",
                    'debit': 0,
                    'credit': self.invoice_id.amount_residual,
                }),
            ],
        }
        
        payment_move = self.env['account.move'].create(move_vals)
        payment_move.action_post()
        
        _logger.info("Payment move created: %s (id=%s), state=%s", 
                    payment_move.name, payment_move.id, payment_move.state)
        
        # Now reconcile the payment with the invoice
        # Get the receivable line from the payment move
        payment_receivable_line = payment_move.line_ids.filtered(
            lambda l: l.account_id.id == receivable_account.id
            and not l.reconciled
        )
        
        # Get unreconciled receivable line from invoice
        invoice_receivable_line = self.invoice_id.line_ids.filtered(
            lambda l: l.account_id.account_type == 'asset_receivable'
            and not l.reconciled
        )
        
        # Reconcile
        if invoice_receivable_line and payment_receivable_line:
            try:
                (invoice_receivable_line + payment_receivable_line).reconcile()
                _logger.info("Reconciliation successful!")
            except Exception as e:
                _logger.error("Reconciliation failed: %s", e)
        
        # Refresh states
        self.invoice_id.invalidate_recordset(['payment_state', 'amount_residual'])
        
        # Check if invoice is now paid
        if self.invoice_id.payment_state == 'paid':
            self.message_post(body=_('Paiement espèces enregistré et réconcilié: %s MRU') % self.total_amount)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Paiement Enregistré ✓'),
                    'message': _('Le paiement de %s MRU a été enregistré et réconcilié avec succès.') % self.total_amount,
                    'type': 'success',
                    'sticky': False,
                }
            }
        else:
            self.message_post(body=_('Paiement créé: %s MRU') % self.total_amount)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Paiement Créé'),
                    'message': _('Paiement créé mais vérifiez la réconciliation.'),
                    'type': 'warning',
                    'sticky': True,
                }
            }

    def action_cancel(self):
        """Cancel billing and linked invoice"""
        for record in self:
            if record.invoice_id:
                if record.invoice_id.state == 'posted':
                    # Need to reverse the invoice for posted invoices
                    if record.invoice_id.payment_state != 'not_paid':
                        raise UserError(_(
                            'Impossible d\'annuler une facture avec des paiements. '
                            'Annulez d\'abord les paiements dans le module Comptabilité.'
                        ))
                record.invoice_id.button_cancel()
            record.message_post(body=_('Facturation annulée'))
        return True
    
    def action_reset_draft(self):
        """Reset to draft"""
        for record in self:
            if record.invoice_id and record.invoice_id.state == 'cancel':
                record.invoice_id.button_draft()
            record.message_post(body=_('Facturation remise en brouillon'))
        return True

    # ==================== VIEW ACTIONS ====================
    
    def _action_view_invoice(self):
        """Return action to view invoice in accounting module"""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Facture'),
            'res_model': 'account.move',
            'res_id': self.invoice_id.id,
            'view_mode': 'form',
            'views': [(False, 'form')],
            'target': 'current',
        }
    
    def action_view_invoice(self):
        """Open the linked invoice in accounting module"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture liée.'))
        return self._action_view_invoice()
    
    def action_view_payments(self):
        """View all payments linked to this billing's invoice"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture liée.'))
        
        payments = self.env['account.payment'].search([
            ('reconciled_invoice_ids', 'in', self.invoice_id.id)
        ])
        
        action = {
            'type': 'ir.actions.act_window',
            'name': _('Paiements'),
            'res_model': 'account.payment',
            'view_mode': 'list,form',
            'domain': [('id', 'in', payments.ids)],
            'context': {'create': False},
        }
        
        if len(payments) == 1:
            action['view_mode'] = 'form'
            action['res_id'] = payments.id
        
        return action
    
    def action_open_reconcile(self):
        """Open reconciliation view for this invoice's partner"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture liée.'))
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Réconciliation'),
            'res_model': 'account.move.line',
            'view_mode': 'list',
            'domain': [
                ('partner_id', '=', self.receiver_partner_id.id),
                ('account_id.reconcile', '=', True),
                ('reconciled', '=', False),
            ],
            'context': {
                'search_default_unreconciled': 1,
            },
        }

    def action_send_invoice_by_email(self):
        """Send invoice by email using Odoo's standard method"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture à envoyer.'))
        
        return self.invoice_id.action_invoice_sent()

    # ==================== SMART BUTTONS DATA ====================
    
    def action_open_in_accounting(self):
        """Open full accounting view for this invoice"""
        self.ensure_one()
        if not self.invoice_id:
            raise UserError(_('Aucune facture liée.'))
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web#id={self.invoice_id.id}&model=account.move&view_type=form',
            'target': 'self',
        }
