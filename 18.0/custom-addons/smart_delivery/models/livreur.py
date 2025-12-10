# -*- coding: utf-8 -*-

from odoo import models, fields, api, _


class DeliveryLivreur(models.Model):
    _name = 'delivery.livreur'
    _description = 'Livreur'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(string='Nom', required=True, tracking=True)
    phone = fields.Char(string='Téléphone', required=True, tracking=True)
    
    vehicle_type = fields.Selection([
        ('motorcycle', 'Moto'),
        ('car', 'Voiture'),
        ('bicycle', 'Vélo'),
        ('truck', 'Camion'),
    ], string='Type de Véhicule', required=True, tracking=True)
    
    availability = fields.Boolean(string='Disponible', default=True, tracking=True)
    rating = fields.Float(string='Note', digits=(2, 1), default=0.0, tracking=True)
    
    current_lat = fields.Float(string='Latitude Actuelle', digits=(10, 7), default=0.0)
    current_long = fields.Float(string='Longitude Actuelle', digits=(10, 7), default=0.0)
    
    verified = fields.Boolean(string='Vérifié', default=False, tracking=True)
    
    order_ids = fields.One2many('delivery.order', 'assigned_livreur_id', string='Commandes')
    order_count = fields.Integer(string='Nombre de Commandes', compute='_compute_order_count')
    
    @api.depends('order_ids')
    def _compute_order_count(self):
        for record in self:
            record.order_count = len(record.order_ids)
    
    def action_view_orders(self):
        """Ouvre la vue des commandes du livreur"""
        self.ensure_one()
        return {
            'name': _('Commandes'),
            'type': 'ir.actions.act_window',
            'res_model': 'delivery.order',
            'view_mode': 'list,form',
            'domain': [('assigned_livreur_id', '=', self.id)],
            'context': {'default_assigned_livreur_id': self.id},
        }

