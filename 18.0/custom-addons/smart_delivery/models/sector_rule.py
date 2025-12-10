# -*- coding: utf-8 -*-

from odoo import models, fields, api


class SectorRule(models.Model):
    _name = 'sector.rule'
    _description = 'Règle de Secteur'
    _rec_name = 'sector_type'

    sector_type = fields.Selection([
        ('standard', 'Standard'),
        ('premium', 'Premium'),
        ('express', 'Express'),
        ('fragile', 'Fragile'),
        ('medical', 'Médical'),
    ], string='Type de Secteur', required=True, unique=True)
    
    otp_required = fields.Boolean(string='OTP Requis', default=False)
    signature_required = fields.Boolean(string='Signature Requise', default=False)
    photo_required = fields.Boolean(string='Photo Requise', default=False)
    biometric_required = fields.Boolean(string='Biométrie Requise', default=False)
    
    description = fields.Text(string='Description')

