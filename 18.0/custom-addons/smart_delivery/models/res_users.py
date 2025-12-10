# -*- coding: utf-8 -*-

from odoo import models, fields, api


class ResUsers(models.Model):
    _inherit = 'res.users'

    livreur_id = fields.One2many('delivery.livreur', 'user_id', string='Livreur')
    is_livreur = fields.Boolean(string='Est un Livreur', compute='_compute_is_livreur', store=False)
    
    @api.depends('livreur_id')
    def _compute_is_livreur(self):
        """Check if user is a livreur"""
        for user in self:
            user.is_livreur = bool(user.livreur_id)
