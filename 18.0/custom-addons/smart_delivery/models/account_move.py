# -*- coding: utf-8 -*-

from odoo import api, fields, models


class AccountMove(models.Model):
    _inherit = 'account.move'

    # Link back to delivery billing
    delivery_billing_ids = fields.One2many(
        'delivery.billing',
        'invoice_id',
        string='Facturations Livraison',
        readonly=True,
    )
    
    delivery_billing_count = fields.Integer(
        compute='_compute_delivery_billing_count',
        string='Facturations',
    )
    
    is_delivery_invoice = fields.Boolean(
        compute='_compute_is_delivery_invoice',
        string='Facture Livraison',
        store=True,
    )
    
    # Enterprise info for delivery invoices (stored for report)
    delivery_enterprise_id = fields.Many2one(
        'delivery.enterprise',
        string='Entreprise Expéditrice',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_name = fields.Char(
        string='Nom Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_logo = fields.Binary(
        string='Logo Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_email = fields.Char(
        string='Email Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_phone = fields.Char(
        string='Téléphone Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_address = fields.Text(
        string='Adresse Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    delivery_enterprise_website = fields.Char(
        string='Site Web Entreprise',
        compute='_compute_delivery_enterprise',
        store=True,
    )
    
    @api.depends('delivery_billing_ids')
    def _compute_delivery_billing_count(self):
        for record in self:
            record.delivery_billing_count = len(record.delivery_billing_ids)
    
    @api.depends('delivery_billing_ids')
    def _compute_is_delivery_invoice(self):
        for record in self:
            record.is_delivery_invoice = bool(record.delivery_billing_ids)
    
    @api.depends('delivery_billing_ids', 'delivery_billing_ids.enterprise_id')
    def _compute_delivery_enterprise(self):
        """Get enterprise info from linked billing for invoice report"""
        for record in self:
            billing = record.delivery_billing_ids[:1]
            if billing and billing.enterprise_id:
                enterprise = billing.enterprise_id
                record.delivery_enterprise_id = enterprise.id
                record.delivery_enterprise_name = enterprise.name
                record.delivery_enterprise_logo = enterprise.logo
                record.delivery_enterprise_email = enterprise.email
                record.delivery_enterprise_phone = enterprise.phone
                # Build full address
                address_parts = []
                if enterprise.address:
                    address_parts.append(enterprise.address)
                if enterprise.city:
                    address_parts.append(enterprise.city)
                record.delivery_enterprise_address = '\n'.join(address_parts) if address_parts else False
                record.delivery_enterprise_website = enterprise.website
            else:
                record.delivery_enterprise_id = False
                record.delivery_enterprise_name = False
                record.delivery_enterprise_logo = False
                record.delivery_enterprise_email = False
                record.delivery_enterprise_phone = False
                record.delivery_enterprise_address = False
                record.delivery_enterprise_website = False

    def action_view_delivery_billings(self):
        """View delivery billings linked to this invoice"""
        self.ensure_one()
        action = {
            'type': 'ir.actions.act_window',
            'name': 'Facturation Livraison',
            'res_model': 'delivery.billing',
            'view_mode': 'list,form',
            'domain': [('invoice_id', '=', self.id)],
            'context': {'create': False},
        }
        if len(self.delivery_billing_ids) == 1:
            action['view_mode'] = 'form'
            action['res_id'] = self.delivery_billing_ids.id
        return action


class AccountPayment(models.Model):
    _inherit = 'account.payment'

    def action_post(self):
        """Override to sync delivery billing state after payment is posted"""
        res = super().action_post()
        
        # Find and update linked delivery billings
        for payment in self:
            for invoice in payment.reconciled_invoice_ids:
                billings = self.env['delivery.billing'].search([
                    ('invoice_id', '=', invoice.id)
                ])
                # Trigger recomputation of state
                billings._compute_state()
        
        return res
