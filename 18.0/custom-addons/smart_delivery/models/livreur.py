# -*- coding: utf-8 -*-

import base64
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class DeliveryLivreur(models.Model):
    _name = 'delivery.livreur'
    _description = 'Livreur'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(string='Nom', required=True, tracking=True)
    phone = fields.Char(string='Téléphone', required=True, tracking=True)
    email = fields.Char(string='Email', tracking=True, 
                        help='Email utilisé comme identifiant de connexion')
    # Password is not stored - used only during creation via inverse
    password = fields.Char(string='Mot de passe', compute='_compute_password', 
                           inverse='_inverse_password', store=False,
                           help='Mot de passe pour la connexion API (non stocké)')
    
    # ==================== REQUIRED IDENTIFICATION DOCUMENTS ====================
    nni = fields.Char(string='NNI (Numéro National d\'Identification)', required=True, 
                      tracking=True, help='Numéro National d\'Identification du livreur')
    nni_photo = fields.Binary(string='Photo NNI', required=True, 
                              help='Photo du document NNI')
    nni_photo_filename = fields.Char(string='Nom fichier NNI')
    livreur_photo = fields.Binary(string='Photo du Livreur', required=True, 
                                  help='Photo d\'identité du livreur')
    livreur_photo_filename = fields.Char(string='Nom fichier photo livreur')
    carte_grise_photo = fields.Binary(string='Photo Carte Grise', required=True, 
                                      help='Photo de la carte grise du véhicule')
    carte_grise_photo_filename = fields.Char(string='Nom fichier carte grise')
    assurance_photo = fields.Binary(string='Photo Assurance', required=True, 
                                    help='Photo du document d\'assurance')
    assurance_photo_filename = fields.Char(string='Nom fichier assurance')
    
    # Registration status for pending approvals
    registration_status = fields.Selection([
        ('pending', 'En attente de vérification'),
        ('approved', 'Approuvé'),
        ('rejected', 'Rejeté'),
    ], string='Statut d\'inscription', default='pending', tracking=True,
       help='Statut de vérification du dossier livreur')
    rejection_reason = fields.Text(string='Motif de rejet', tracking=True)
    
    _sql_constraints = [
        ('nni_unique', 'UNIQUE(nni)', 'Ce NNI est déjà utilisé par un autre livreur!'),
    ]
    
    def _compute_password(self):
        """Password is never read from database"""
        for record in self:
            record.password = ''
    
    def _inverse_password(self):
        """Set password on the linked user"""
        for record in self:
            if record.password and record.user_id:
                record.user_id.sudo().with_context(active_test=False).write({'password': record.password})
    
    user_id = fields.Many2one('res.users', string='Utilisateur Système', readonly=True, 
                              tracking=True, help='Utilisateur système créé automatiquement',
                              context={'active_test': False})
    
    _sql_constraints = [
        ('user_unique', 'UNIQUE(user_id)', 'Un utilisateur ne peut être associé qu\'à un seul livreur!'),
        ('email_unique', 'UNIQUE(email)', 'Cet email est déjà utilisé par un autre livreur!'),
    ]
    
    @api.constrains('user_id')
    def _check_user_unique(self):
        """Ensure a user can only be linked to one livreur"""
        for livreur in self:
            if livreur.user_id:
                existing = self.search([
                    ('user_id', '=', livreur.user_id.id),
                    ('id', '!=', livreur.id)
                ], limit=1)
                if existing:
                    raise ValidationError(_('Cet utilisateur est déjà associé à un autre livreur: %s') % existing.name)
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to automatically create a system user for the livreur"""
        for vals in vals_list:
            # Only create user if email is provided and user_id not already set
            if vals.get('email') and not vals.get('user_id'):
                # Check if a user with this email already exists (including archived)
                existing_user = self.env['res.users'].sudo().with_context(active_test=False).search([
                    '|', ('login', '=', vals['email']), ('email', '=', vals['email'])
                ], limit=1)
                
                if existing_user:
                    if existing_user.active:
                        # Update user to have livreur group
                        livreur_group = self.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
                        if livreur_group:
                            existing_user.sudo().write({
                                'groups_id': [(4, livreur_group.id)]
                            })
                        vals['user_id'] = existing_user.id
                    else:
                        raise ValidationError(_('Un utilisateur archivé existe avec cet email: %s. Contactez l\'administrateur.') % vals['email'])
                else:
                    # Create a new user for this livreur with livreur group
                    # Livreur group only - no portal or internal user access
                    livreur_group = self.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
                    group_ids = [livreur_group.id] if livreur_group else []
                    
                    # Create user as active first, then deactivate if pending
                    user_vals = {
                        'name': vals.get('name'),
                        'login': vals.get('email'),
                        'email': vals.get('email'),
                        'phone': vals.get('phone'),
                        'password': vals.get('password', 'livreur123'),
                        'groups_id': [(6, 0, group_ids)],
                        'active': True,  # Create as active first
                    }
                    user = self.env['res.users'].sudo().create(user_vals)
                    vals['user_id'] = user.id
                    
                    # Deactivate user if registration is pending
                    if vals.get('registration_status', 'pending') != 'approved':
                        user.sudo().write({'active': False})
                
                # Clear password from vals (we don't store it in livreur)
                vals.pop('password', None)
        
        return super().create(vals_list)
    
    def write(self, vals):
        """Override write to update user if email/name changes"""
        result = super().write(vals)
        
        # Update password if provided
        if vals.get('password'):
            for livreur in self:
                if livreur.user_id:
                    livreur.user_id.sudo().with_context(active_test=False).write({'password': vals['password']})
        
        # Update user email/name if changed
        if vals.get('email') or vals.get('name'):
            for livreur in self:
                if livreur.user_id:
                    update_vals = {}
                    if vals.get('email'):
                        update_vals['login'] = vals['email']
                        update_vals['email'] = vals['email']
                    if vals.get('name'):
                        update_vals['name'] = vals['name']
                    if update_vals:
                        livreur.user_id.sudo().with_context(active_test=False).write(update_vals)
        
        return result
    
    def action_reset_password(self):
        """Send password reset email to livreur"""
        self.ensure_one()
        if self.user_id:
            self.user_id.action_reset_password()
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Email envoyé'),
                    'message': _('Un email de réinitialisation du mot de passe a été envoyé à %s') % self.email,
                    'type': 'success',
                }
            }
    
    vehicle_type = fields.Selection([
        ('motorcycle', 'Moto'),
        ('car', 'Voiture'),
        ('bicycle', 'Vélo'),
        ('truck', 'Camion'),
    ], string='Type de Véhicule', required=True, tracking=True)
    
    # Sector rules this livreur can handle (multiple selection)
    sector_ids = fields.Many2many(
        'sector.rule',
        'livreur_sector_rule_rel',
        'livreur_id',
        'sector_rule_id',
        string='Types de Secteur',
        help='Les types de secteurs que ce livreur peut gérer',
        tracking=True,
    )
    
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
    
    @api.model
    def _assign_default_sector(self):
        """Assign default sector (standard) to livreurs that don't have any sector.
        This is called during module installation/upgrade.
        """
        # Get standard sector rule
        standard_sector = self.env['sector.rule'].search([('sector_type', '=', 'standard')], limit=1)
        if not standard_sector:
            return
        
        # Find livreurs without any sector
        livreurs_without_sector = self.search([('sector_ids', '=', False)])
        
        # Assign standard sector to them
        for livreur in livreurs_without_sector:
            livreur.sector_ids = [(4, standard_sector.id)]
        
        return True
    
    # ==================== REGISTRATION APPROVAL ACTIONS ====================
    
    def action_approve_registration(self):
        """Approve livreur registration - sets status to approved and enables the account"""
        self.ensure_one()
        if self.registration_status != 'pending':
            raise ValidationError(_('Seules les inscriptions en attente peuvent être approuvées.'))
        
        self.write({
            'registration_status': 'approved',
            'verified': True,
            'availability': True,
            'rejection_reason': False,
        })
        
        # Activate the user account
        if self.user_id:
            self.user_id.sudo().with_context(active_test=False).write({'active': True})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Inscription Approuvée'),
                'message': _('L\'inscription du livreur %s a été approuvée. Le compte utilisateur est maintenant actif.') % self.name,
                'type': 'success',
                'sticky': False,
            }
        }
    
    def action_reject_registration(self):
        """Open wizard to reject livreur registration with a reason"""
        self.ensure_one()
        if self.registration_status != 'pending':
            raise ValidationError(_('Seules les inscriptions en attente peuvent être rejetées.'))
        
        return {
            'name': _('Rejeter l\'inscription'),
            'type': 'ir.actions.act_window',
            'res_model': 'livreur.reject.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_livreur_id': self.id},
        }
    
    def action_set_pending(self):
        """Reset registration status to pending (for re-review)"""
        self.ensure_one()
        self.write({
            'registration_status': 'pending',
            'verified': False,
            'availability': False,
        })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Statut modifié'),
                'message': _('L\'inscription du livreur %s est maintenant en attente de vérification.') % self.name,
                'type': 'warning',
                'sticky': False,
            }
        }

