# -*- coding: utf-8 -*-

from odoo import models, fields, api


class ResUsers(models.Model):
    _inherit = 'res.users'

    livreur_id = fields.One2many('delivery.livreur', 'user_id', string='Livreur')
    
    # Computed field for filtering and display
    delivery_user_type = fields.Selection([
        ('admin', 'Administrateur'),
        ('enterprise', 'Entreprise'),
        ('livreur', 'Livreur'),
    ], string='Rôle Smart Delivery', compute='_compute_delivery_user_type', 
       inverse='_inverse_delivery_user_type', store=True)
    
    # Password field for setting password in form
    set_password = fields.Char(
        string='Nouveau mot de passe',
        help='Entrez un mot de passe pour cet utilisateur',
        store=False,
    )
    
    @api.depends('groups_id')
    def _compute_delivery_user_type(self):
        """Compute the delivery user type from groups"""
        admin_group = self.env.ref('smart_delivery.group_admin', raise_if_not_found=False)
        enterprise_group = self.env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
        livreur_group = self.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
        
        for user in self:
            if admin_group and admin_group in user.groups_id:
                user.delivery_user_type = 'admin'
            elif enterprise_group and enterprise_group in user.groups_id:
                user.delivery_user_type = 'enterprise'
            elif livreur_group and livreur_group in user.groups_id:
                user.delivery_user_type = 'livreur'
            else:
                user.delivery_user_type = False
    
    def _inverse_delivery_user_type(self):
        """Set the appropriate group based on selected role"""
        admin_group = self.env.ref('smart_delivery.group_admin', raise_if_not_found=False)
        enterprise_group = self.env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
        livreur_group = self.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
        
        for user in self:
            # Build list of groups to remove and add
            groups_to_remove = []
            groups_to_add = []
            
            # Remove all delivery groups first
            if admin_group and admin_group in user.groups_id:
                groups_to_remove.append((3, admin_group.id))
            if enterprise_group and enterprise_group in user.groups_id:
                groups_to_remove.append((3, enterprise_group.id))
            if livreur_group and livreur_group in user.groups_id:
                groups_to_remove.append((3, livreur_group.id))
            
            # Add the selected group
            if user.delivery_user_type == 'admin' and admin_group:
                groups_to_add.append((4, admin_group.id))
            elif user.delivery_user_type == 'enterprise' and enterprise_group:
                groups_to_add.append((4, enterprise_group.id))
            elif user.delivery_user_type == 'livreur' and livreur_group:
                groups_to_add.append((4, livreur_group.id))
            
            if groups_to_remove or groups_to_add:
                user.sudo().write({'groups_id': groups_to_remove + groups_to_add})
    
    def write(self, vals):
        """Override write to handle password setting"""
        # Handle set_password field
        if 'set_password' in vals and vals['set_password']:
            vals['password'] = vals.pop('set_password')
        elif 'set_password' in vals:
            vals.pop('set_password')
        return super().write(vals)
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to handle password and use email as login"""
        for vals in vals_list:
            # Use email as login if login not provided
            if not vals.get('login') and vals.get('email'):
                vals['login'] = vals['email']
            # Handle set_password field
            if 'set_password' in vals and vals['set_password']:
                vals['password'] = vals.pop('set_password')
            elif 'set_password' in vals:
                vals.pop('set_password')
        return super().create(vals_list)
    
    @api.onchange('email')
    def _onchange_email_set_login(self):
        """Auto-set login when email changes"""
        if self.email and not self.login:
            self.login = self.email
    
    def get_delivery_user_type(self):
        """Return the user type for Smart Delivery API"""
        self.ensure_one()
        return self.delivery_user_type or 'other'
