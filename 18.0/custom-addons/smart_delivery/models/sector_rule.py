# -*- coding: utf-8 -*-

from odoo import models, fields, api


class SectorRule(models.Model):
    _name = 'sector.rule'
    _description = 'Règle de Secteur'
    _rec_name = 'sector_type'

    # Free text sector type so new types can be created dynamically
    # (existing data will still use the old codes like 'standard', 'premium', etc.)
    sector_type = fields.Char(string='Type de Secteur', required=True)
    
    otp_required = fields.Boolean(string='OTP Requis', default=False)
    signature_required = fields.Boolean(string='Signature Requise', default=False)
    photo_required = fields.Boolean(string='Photo Requise', default=False)
    biometric_required = fields.Boolean(string='Biométrie Requise', default=False)
    
    # Pricing fields
    base_price = fields.Float(
        string='Prix de Base', 
        digits=(10, 2), 
        default=50.0,
        help="Tarif de base pour ce type de livraison (en MRU)"
    )
    distance_fee_per_km = fields.Float(
        string='Frais par km (au-delà de 5km)', 
        digits=(10, 2), 
        default=10.0,
        help="Frais supplémentaires par kilomètre au-delà des 5 premiers kilomètres gratuits"
    )
    free_distance_km = fields.Float(
        string='Distance gratuite (km)', 
        digits=(10, 2), 
        default=5.0,
        help="Distance en kilomètres incluse dans le prix de base"
    )
    
    description = fields.Text(string='Description')
    
    # Related livreurs
    livreur_ids = fields.Many2many(
        'delivery.livreur',
        'livreur_sector_rule_rel',
        'sector_rule_id',
        'livreur_id',
        string='Livreurs',
    )
    livreur_count = fields.Integer(string='Nombre de Livreurs', compute='_compute_livreur_count')
    
    @api.depends('livreur_ids')
    def _compute_livreur_count(self):
        for record in self:
            record.livreur_count = len(record.livreur_ids)
    
    def action_view_livreurs(self):
        """Open the livreurs view for this sector"""
        self.ensure_one()
        return {
            'name': f'Livreurs - {self.sector_type}',
            'type': 'ir.actions.act_window',
            'res_model': 'delivery.livreur',
            'view_mode': 'list,form',
            'domain': [('sector_ids', 'in', [self.id])],
            'context': {'default_sector_ids': [(4, self.id)]},
        }
    
    _sql_constraints = [
        ('sector_type_unique', 'UNIQUE(sector_type)', 
         'Une règle existe déjà pour ce type de secteur!')
    ]
    
    @api.model
    def init(self):
        """Initialise les règles de secteur par défaut au chargement du module"""
        super().init()
        self._init_default_rules()
    
    @api.model
    def _init_default_rules(self):
        """Crée ou met à jour les règles de secteur par défaut"""
        default_rules = [
            {
                'sector_type': 'standard',
                'otp_required': False,
                'signature_required': False,
                'photo_required': False,
                'biometric_required': False,
                'base_price': 50.0,
                'distance_fee_per_km': 10.0,
                'free_distance_km': 5.0,
                'description': 'Livraison standard sans exigences particulières. Dépôt simple au destinataire.',
            },
            {
                'sector_type': 'premium',
                'otp_required': True,
                'signature_required': True,
                'photo_required': False,
                'biometric_required': False,
                'base_price': 100.0,
                'distance_fee_per_km': 10.0,
                'free_distance_km': 5.0,
                'description': 'Livraison premium nécessitant une vérification OTP et une signature du destinataire.',
            },
            {
                'sector_type': 'express',
                'otp_required': True,
                'signature_required': False,
                'photo_required': True,
                'biometric_required': False,
                'base_price': 150.0,
                'distance_fee_per_km': 15.0,
                'free_distance_km': 5.0,
                'description': 'Livraison express avec vérification OTP et photo de preuve de livraison.',
            },
            {
                'sector_type': 'fragile',
                'otp_required': True,
                'signature_required': True,
                'photo_required': True,
                'biometric_required': False,
                'base_price': 120.0,
                'distance_fee_per_km': 12.0,
                'free_distance_km': 5.0,
                'description': "Livraison de colis fragiles avec OTP, signature et photo obligatoires pour prouver l'état du colis.",
            },
            {
                'sector_type': 'medical',
                'otp_required': True,
                'signature_required': True,
                'photo_required': True,
                'biometric_required': True,
                'base_price': 200.0,
                'distance_fee_per_km': 20.0,
                'free_distance_km': 5.0,
                'description': 'Livraison médicale avec protocole complet: OTP, signature, photo et vérification biométrique du destinataire.',
            },
        ]
        
        for rule_vals in default_rules:
            existing_rule = self.search([
                ('sector_type', '=', rule_vals['sector_type'])
            ], limit=1)
            
            if existing_rule:
                # Mettre à jour seulement si les valeurs ont changé
                existing_rule.write(rule_vals)
            else:
                self.create(rule_vals)

