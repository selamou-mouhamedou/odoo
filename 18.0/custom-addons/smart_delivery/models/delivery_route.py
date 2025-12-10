# -*- coding: utf-8 -*-

from odoo import models, fields, api


class DeliveryRoute(models.Model):
    _name = 'delivery.route'
    _description = 'Itinéraire de Livraison'
    _order = 'sequence, id'

    order_id = fields.Many2one('delivery.order', string='Commande', required=True, ondelete='cascade')
    
    waypoint_lat = fields.Float(string='Latitude Point de Passage', required=True, digits=(10, 7))
    waypoint_long = fields.Float(string='Longitude Point de Passage', required=True, digits=(10, 7))
    
    sequence = fields.Integer(string='Séquence', default=10)
    
    name = fields.Char(string='Nom du Point', compute='_compute_name', store=True)
    
    @api.depends('waypoint_lat', 'waypoint_long')
    def _compute_name(self):
        for record in self:
            record.name = f"Point ({record.waypoint_lat:.5f}, {record.waypoint_long:.5f})"

