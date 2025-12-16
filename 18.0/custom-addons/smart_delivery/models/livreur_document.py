# -*- coding: utf-8 -*-

from odoo import models, fields, api


class LivreurDocument(models.Model):
    _name = 'livreur.document'
    _description = 'Document du Livreur'
    _order = 'sequence, id'

    livreur_id = fields.Many2one(
        'delivery.livreur', 
        string='Livreur',
        required=True, 
        ondelete='cascade',
        index=True
    )
    name = fields.Char(
        string='Nom du Document', 
        required=True,
        help='Nom ou type du document (ex: NNI, Carte Grise, Permis, Assurance, etc.)'
    )
    photo = fields.Binary(
        string='Photo du Document', 
        required=True,
        attachment=True
    )
    photo_filename = fields.Char(string='Nom du fichier')
    sequence = fields.Integer(string='Séquence', default=10)
    
    # Optional: track document verification status
    is_verified = fields.Boolean(
        string='Vérifié', 
        default=False,
        help='Indique si ce document a été vérifié par un administrateur'
    )
    notes = fields.Text(
        string='Notes',
        help='Notes ou commentaires sur ce document'
    )
