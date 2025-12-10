# -*- coding: utf-8 -*-

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
    
    def _compute_password(self):
        """Password is never read from database"""
        for record in self:
            record.password = ''
    
    def _inverse_password(self):
        """Set password on the linked user"""
        for record in self:
            if record.password and record.user_id:
                record.user_id.sudo().write({'password': record.password})
    
    user_id = fields.Many2one('res.users', string='Utilisateur Système', readonly=True, 
                              tracking=True, help='Utilisateur système créé automatiquement')
    
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
                # Check if a user with this email already exists
                existing_user = self.env['res.users'].sudo().search([
                    '|', ('login', '=', vals['email']), ('email', '=', vals['email'])
                ], limit=1)
                
                if existing_user:
                    vals['user_id'] = existing_user.id
                else:
                    # Create a new user for this livreur
                    user_vals = {
                        'name': vals.get('name'),
                        'login': vals.get('email'),
                        'email': vals.get('email'),
                        'phone': vals.get('phone'),
                        'password': vals.get('password', 'livreur123'),  # Default password if not provided
                        'groups_id': [(6, 0, [self.env.ref('base.group_portal').id])],  # Portal user
                    }
                    user = self.env['res.users'].sudo().create(user_vals)
                    vals['user_id'] = user.id
                
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
                    livreur.user_id.sudo().write({'password': vals['password']})
        
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
                        livreur.user_id.sudo().write(update_vals)
        
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

