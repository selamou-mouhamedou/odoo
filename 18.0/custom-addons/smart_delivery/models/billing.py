# -*- coding: utf-8 -*-

from odoo import models, fields, api


class DeliveryBilling(models.Model):
    _name = 'delivery.billing'
    _description = 'Facturation de Livraison'
    _order = 'id desc'

    order_id = fields.Many2one(
        'delivery.order', 
        string='Commande', 
        required=True, 
        ondelete='cascade',
        index=True,
    )
    
    @api.model
    def default_get(self, fields_list):
        """Override to safely handle default_order_id from context"""
        res = super().default_get(fields_list)
        if 'order_id' in fields_list and 'default_order_id' not in res:
            ctx = self.env.context
            if 'default_order_id' in ctx:
                res['order_id'] = ctx.get('default_order_id')
            elif 'active_id' in ctx and ctx.get('active_model') == 'delivery.order':
                res['order_id'] = ctx.get('active_id')
            elif 'active_ids' in ctx and ctx.get('active_model') == 'delivery.order' and ctx.get('active_ids'):
                res['order_id'] = ctx.get('active_ids')[0]
        return res
    
    # Billing details
    distance_km = fields.Float(string='Distance (km)', digits=(10, 2))
    base_tariff = fields.Float(string='Tarif de Base', digits=(10, 2))
    extra_fee = fields.Float(string='Frais Supplémentaires', digits=(10, 2), default=0.0)
    total_amount = fields.Float(string='Montant Total', digits=(10, 2), required=True)
    commission = fields.Float(string='Commission', digits=(10, 2))
    
    # Status tracking
    state = fields.Selection([
        ('draft', 'Brouillon'),
        ('confirmed', 'Confirmé'),
        ('paid', 'Payé'),
        ('cancelled', 'Annulé'),
    ], string='État', default='draft', tracking=True)
    
    # Optional notes
    notes = fields.Text(string='Notes')
    
    def action_confirm(self):
        """Confirm the billing"""
        self.write({'state': 'confirmed'})
    
    def action_mark_paid(self):
        """Mark billing as paid"""
        self.write({'state': 'paid'})
    
    def action_cancel(self):
        """Cancel the billing"""
        self.write({'state': 'cancelled'})
    
    def action_reset_draft(self):
        """Reset to draft"""
        self.write({'state': 'draft'})
