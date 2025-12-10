# -*- coding: utf-8 -*-

from odoo import SUPERUSER_ID, api
import logging

_logger = logging.getLogger(__name__)


def pre_init_hook(env):
    """Nettoie les données avant l'installation/mise à jour du module"""
    # Pas besoin d'action ici pour l'instant
    pass


def post_init_hook(env):
    """Initialise les règles de secteur par défaut après l'installation du module"""
    _create_default_sector_rules(env)


def post_load():
    """Hook appelé après le chargement du module - utile pour les mises à jour"""
    pass


def uninstall_hook(env):
    """Nettoie les données lors de la désinstallation"""
    pass


def _create_default_sector_rules(env):
    """Crée ou met à jour les règles de secteur par défaut"""
    SectorRule = env['sector.rule']
    
    # Définition des règles par défaut
    default_rules = [
        {
            'sector_type': 'standard',
            'otp_required': False,
            'signature_required': False,
            'photo_required': False,
            'biometric_required': False,
            'description': 'Livraison standard sans exigences particulières. Dépôt simple au destinataire.',
        },
        {
            'sector_type': 'premium',
            'otp_required': True,
            'signature_required': True,
            'photo_required': False,
            'biometric_required': False,
            'description': 'Livraison premium nécessitant une vérification OTP et une signature du destinataire.',
        },
        {
            'sector_type': 'express',
            'otp_required': True,
            'signature_required': False,
            'photo_required': True,
            'biometric_required': False,
            'description': 'Livraison express avec vérification OTP et photo de preuve de livraison.',
        },
        {
            'sector_type': 'fragile',
            'otp_required': True,
            'signature_required': True,
            'photo_required': True,
            'biometric_required': False,
            'description': 'Livraison de colis fragiles avec OTP, signature et photo obligatoires pour prouver l\'état du colis.',
        },
        {
            'sector_type': 'medical',
            'otp_required': True,
            'signature_required': True,
            'photo_required': True,
            'biometric_required': True,
            'description': 'Livraison médicale avec protocole complet: OTP, signature, photo et vérification biométrique du destinataire.',
        },
    ]
    
    for rule_vals in default_rules:
        # Chercher si la règle existe déjà
        existing_rule = SectorRule.search([
            ('sector_type', '=', rule_vals['sector_type'])
        ], limit=1)
        
        if existing_rule:
            # Mettre à jour la règle existante
            existing_rule.write(rule_vals)
        else:
            # Créer la nouvelle règle
            SectorRule.create(rule_vals)
