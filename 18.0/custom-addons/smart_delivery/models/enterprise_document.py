# -*- coding: utf-8 -*-

from odoo import models, fields, api


class EnterpriseDocument(models.Model):
    _name = 'enterprise.document'
    _description = 'Document de l\'Entreprise'
    _order = 'sequence, id'

    enterprise_id = fields.Many2one(
        'delivery.enterprise', 
        string='Entreprise',
        required=True, 
        ondelete='cascade',
        index=True
    )
    name = fields.Char(
        string='Nom du Document', 
        required=True,
        help='Nom ou type du document (ex: Registre de Commerce, NIF, Licence, etc.)'
    )
    photo = fields.Binary(
        string='Photo/Scan du Document', 
        required=True,
        attachment=True
    )
    photo_filename = fields.Char(string='Nom du fichier')
    sequence = fields.Integer(string='Séquence', default=10)
    
    # Track document verification status
    is_verified = fields.Boolean(
        string='Vérifié', 
        default=False,
        help='Indique si ce document a été vérifié par un administrateur'
    )
    notes = fields.Text(
        string='Notes',
        help='Notes ou commentaires sur ce document'
    )
