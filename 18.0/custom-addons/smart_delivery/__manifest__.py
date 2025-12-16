# -*- coding: utf-8 -*-
{
    'name': 'Smart Delivery',
    'version': '18.0.1.9.0',
    'category': 'Delivery',
    'summary': 'Système de livraison intelligent avec dispatching automatique',
    'description': """
        Module de gestion de livraison intelligent avec:
        - Dispatching automatique de livreurs
        - Validation OTP, signature, photo, biométrie
        - Intégration comptabilité Odoo native (account.move)
        - API REST avec authentification JWT
        - Suivi GPS en temps réel
        
        v1.9.0: Documents dynamiques pour inscription livreur ET entreprise
        - Nouveau modèle livreur.document pour documents flexibles livreur
        - Nouveau modèle enterprise.document pour documents flexibles entreprise
        - Les livreurs/entreprises peuvent ajouter n'importe quel type de document
        - Migration automatique des anciens documents livreur
        - API mise à jour pour accepter tableau de documents
        
        v1.7.0: API Livreur pour gestion factures et paiements
        - GET /livreur/orders/{id}/billing - Info facturation
        - POST /livreur/orders/{id}/confirm-invoice - Confirmer facture
        - POST /livreur/orders/{id}/confirm-payment - Confirmer paiement COD
        - GET /livreur/orders/{id}/invoice-pdf - Télécharger PDF
        
        v1.6.0: Rapport facture personnalisé avec infos entreprise
        - Logo de l'entreprise expéditrice sur les factures
        - Nom, email, téléphone, adresse de l'entreprise
        - Rapport PDF personnalisé "Facture Livraison"
        
        v1.5.0: Intégration directe avec le module Comptabilité Odoo
        - Factures générées dans account.move
        - Paiements via account.payment
        - Réconciliation automatique
        - Smart buttons sur les factures
    """,
    'author': 'Smart Delivery Team',
    'website': 'https://www.odoo.com',
    'depends': ['base', 'web', 'mail', 'contacts', 'account', 'sale'],
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
        'data/account_data.xml',
        'data/product_data.xml',
        # Reports
        'report/delivery_invoice_report.xml',
        # Views
        'views/delivery_order_views.xml',
        'views/livreur_views.xml',
        'views/enterprise_views.xml',
        'views/condition_views.xml',
        'views/sector_rule_views.xml',
        'views/billing_views.xml',
        'views/account_move_views.xml',
        'views/api_log_views.xml',
        'views/res_users_views.xml',
        'views/menu.xml',
    ],
    'demo': [
        'data/demo_invoicing.xml',
    ],
    'pre_init_hook': 'pre_init_hook',
    'post_init_hook': 'post_init_hook',
    'uninstall_hook': 'uninstall_hook',
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'LGPL-3',
}

