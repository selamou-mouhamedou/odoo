# -*- coding: utf-8 -*-

from odoo import models, fields, api


class ResPartner(models.Model):
    _inherit = 'res.partner'
    
    # Link to delivery enterprise
    delivery_enterprise_id = fields.One2many(
        'delivery.enterprise', 'partner_id', 
        string='Entreprise de Livraison'
    )
    
    is_delivery_enterprise = fields.Boolean(
        string='Est une entreprise de livraison',
        compute='_compute_is_delivery_enterprise',
        search='_search_is_delivery_enterprise',
        store=False
    )
    
    def _compute_is_delivery_enterprise(self):
        """Check if this partner is linked to an approved delivery enterprise"""
        for partner in self:
            enterprise = self.env['delivery.enterprise'].sudo().search([
                ('partner_id', '=', partner.id),
                ('registration_status', '=', 'approved')
            ], limit=1)
            partner.is_delivery_enterprise = bool(enterprise)
    
    def _search_is_delivery_enterprise(self, operator, value):
        """Allow searching on is_delivery_enterprise field"""
        # Get all partner IDs from approved enterprises
        enterprises = self.env['delivery.enterprise'].sudo().search([
            ('registration_status', '=', 'approved')
        ])
        partner_ids = enterprises.mapped('partner_id').ids
        
        if (operator == '=' and value) or (operator == '!=' and not value):
            return [('id', 'in', partner_ids)]
        else:
            return [('id', 'not in', partner_ids)]
