# -*- coding: utf-8 -*-

from odoo import models, fields, api


class DeliveryCondition(models.Model):
    _name = 'delivery.condition'
    _description = 'Condition de Livraison'

    order_id = fields.Many2one('delivery.order', string='Commande', required=True, ondelete='cascade')
    
    @api.model
    def default_get(self, fields_list):
        """Override to safely handle default_order_id from context"""
        res = super().default_get(fields_list)
        # Safely get default_order_id from context, handling cases where active_id might not be available
        if 'order_id' in fields_list and 'order_id' not in res:
            # Try to get from context, but handle if active_id is not defined
            ctx = self.env.context
            if 'default_order_id' in ctx:
                res['order_id'] = ctx.get('default_order_id')
            elif 'active_id' in ctx and ctx.get('active_model') == 'delivery.order':
                res['order_id'] = ctx.get('active_id')
            elif 'active_ids' in ctx and ctx.get('active_model') == 'delivery.order' and ctx.get('active_ids'):
                res['order_id'] = ctx.get('active_ids')[0]
        return res
    
    otp_value = fields.Char(string='Valeur OTP')
    otp_verified = fields.Boolean(string='OTP Vérifié', default=False)
    
    signature_file = fields.Binary(string='Fichier Signature')
    signature_filename = fields.Char(string='Nom du Fichier Signature')
    
    photo_url = fields.Char(string='URL Photo')
    
    biometric_score = fields.Float(string='Score Biométrique', digits=(3, 2))
    
    validated = fields.Boolean(string='Validé', default=False)
    
    @api.model
    def verify_otp(self, order_id, otp_value):
        """Vérifie l'OTP pour une commande"""
        condition = self.search([('order_id', '=', order_id)], limit=1)
        if not condition:
            return False
        
        if condition.otp_value == otp_value:
            condition.write({'otp_verified': True})
            return True
        return False

