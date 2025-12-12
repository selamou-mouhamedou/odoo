# -*- coding: utf-8 -*-
{
    'name': 'Smart Delivery',
    'version': '18.0.1.0.6',
    'category': 'Delivery',
    'summary': 'Système de livraison intelligent avec dispatching automatique',
    'description': """
        Module de gestion de livraison intelligent avec:
        - Dispatching automatique de livreurs
        - Validation OTP, signature, photo, biométrie
        - Gestion de facturation
        - API REST avec authentification JWT
        - Suivi GPS en temps réel
    """,
    'author': 'Smart Delivery Team',
    'website': 'https://www.odoo.com',
    'depends': ['base', 'web', 'mail', 'contacts'],
    'external_dependencies': {
        'python': ['PyJWT', 'cryptography'],
    },
    'data': [
        # Security - groups first, then access rules, then record rules
        'security/security_groups.xml',
        'security/ir.model.access.csv',
        'security/security_rules.xml',
        # Data
        'data/delivery_data.xml',
        # Views
        'views/delivery_order_views.xml',
        'views/livreur_views.xml',
        'views/enterprise_views.xml',
        'views/condition_views.xml',
        'views/sector_rule_views.xml',
        'views/billing_views.xml',
        'views/api_log_views.xml',
        'views/res_users_views.xml',
        'views/menu.xml',
    ],
    'pre_init_hook': 'pre_init_hook',
    'post_init_hook': 'post_init_hook',
    'uninstall_hook': 'uninstall_hook',
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'LGPL-3',
}

