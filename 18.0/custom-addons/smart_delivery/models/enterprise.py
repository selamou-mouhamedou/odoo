# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class DeliveryEnterprise(models.Model):
    _name = 'delivery.enterprise'
    _description = 'Entreprise de Livraison'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'

    name = fields.Char(string='Nom de l\'entreprise', required=True, tracking=True)
    email = fields.Char(string='Email', required=True, tracking=True,
                        help='Email utilisé comme identifiant de connexion')
    phone = fields.Char(string='Téléphone', required=True, tracking=True)
    
    # Logo field
    logo = fields.Binary(string='Logo de l\'entreprise', attachment=True,
                         help='Logo de l\'entreprise (recommandé: 256x256 pixels)')
    logo_filename = fields.Char(string='Nom fichier logo')
    
    # Password is not stored - used only during creation
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
    
    # Linked user
    user_id = fields.Many2one('res.users', string='Utilisateur Système', readonly=True,
                              tracking=True, help='Utilisateur système créé automatiquement')
    partner_id = fields.Many2one('res.partner', string='Partenaire', readonly=True,
                                 tracking=True, help='Contact partenaire créé automatiquement')
    
    # Registration status
    registration_status = fields.Selection([
        ('pending', 'En attente de vérification'),
        ('approved', 'Approuvé'),
        ('rejected', 'Rejeté'),
    ], string='Statut d\'inscription', default='pending', tracking=True,
       help='Statut de vérification du dossier entreprise')
    rejection_reason = fields.Text(string='Motif de rejet', tracking=True)
    
    # Business info
    address = fields.Text(string='Adresse')
    city = fields.Char(string='Ville')
    website = fields.Char(string='Site web')
    description = fields.Text(string='Description de l\'activité')
    
    # Statistics
    order_count = fields.Integer(string='Nombre de Commandes', compute='_compute_order_count')
    
    _sql_constraints = [
        ('email_unique', 'UNIQUE(email)', 'Cet email est déjà utilisé par une autre entreprise!'),
        ('user_unique', 'UNIQUE(user_id)', 'Un utilisateur ne peut être associé qu\'à une seule entreprise!'),
    ]
    
    @api.depends('partner_id')
    def _compute_order_count(self):
        """Count orders linked to this enterprise's partner"""
        for record in self:
            if record.partner_id:
                count = self.env['delivery.order'].sudo().search_count([
                    '|',
                    ('sender_id', '=', record.partner_id.id),
                    ('sender_id.parent_id', '=', record.partner_id.id)
                ])
                record.order_count = count
            else:
                record.order_count = 0
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to automatically create partner and user for the enterprise"""
        for vals in vals_list:
            # Only create user if email is provided and user_id not already set
            if vals.get('email') and not vals.get('user_id'):
                email = vals['email']
                
                # Check if a user with this email already exists
                existing_user = self.env['res.users'].sudo().search([
                    '|', ('login', '=', email), ('email', '=', email)
                ], limit=1)
                
                if existing_user:
                    raise ValidationError(_('Un utilisateur existe déjà avec cet email: %s') % email)
                
                # Create partner first
                partner_vals = {
                    'name': vals.get('name'),
                    'email': email,
                    'phone': vals.get('phone'),
                    'is_company': True,
                    'image_1920': vals.get('logo'),
                    'street': vals.get('address'),
                    'city': vals.get('city'),
                    'website': vals.get('website'),
                    'comment': vals.get('description'),
                }
                partner = self.env['res.partner'].sudo().create(partner_vals)
                vals['partner_id'] = partner.id
                
                # Create user with enterprise group
                enterprise_group = self.env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
                base_user_group = self.env.ref('base.group_user', raise_if_not_found=False)
                group_ids = []
                if enterprise_group:
                    group_ids.append(enterprise_group.id)
                if base_user_group:
                    group_ids.append(base_user_group.id)
                
                user_vals = {
                    'name': vals.get('name'),
                    'login': email,
                    'email': email,
                    'phone': vals.get('phone'),
                    'password': vals.get('password', 'enterprise123'),
                    'partner_id': partner.id,
                    'groups_id': [(6, 0, group_ids)],
                    'active': vals.get('registration_status', 'pending') == 'approved',
                }
                user = self.env['res.users'].sudo().create(user_vals)
                vals['user_id'] = user.id
                
                # Clear password from vals (we don't store it)
                vals.pop('password', None)
        
        return super().create(vals_list)
    
    def write(self, vals):
        """Override write to sync changes with user/partner"""
        result = super().write(vals)
        
        # Update password if provided
        if vals.get('password'):
            for enterprise in self:
                if enterprise.user_id:
                    enterprise.user_id.sudo().write({'password': vals['password']})
        
        # Sync changes to partner and user
        for enterprise in self:
            # Update partner
            if enterprise.partner_id:
                partner_updates = {}
                if vals.get('name'):
                    partner_updates['name'] = vals['name']
                if vals.get('email'):
                    partner_updates['email'] = vals['email']
                if vals.get('phone'):
                    partner_updates['phone'] = vals['phone']
                if vals.get('logo'):
                    partner_updates['image_1920'] = vals['logo']
                if vals.get('address'):
                    partner_updates['street'] = vals['address']
                if vals.get('city'):
                    partner_updates['city'] = vals['city']
                if vals.get('website'):
                    partner_updates['website'] = vals['website']
                if vals.get('description'):
                    partner_updates['comment'] = vals['description']
                if partner_updates:
                    enterprise.partner_id.sudo().write(partner_updates)
            
            # Update user
            if enterprise.user_id:
                user_updates = {}
                if vals.get('name'):
                    user_updates['name'] = vals['name']
                if vals.get('email'):
                    user_updates['login'] = vals['email']
                    user_updates['email'] = vals['email']
                if vals.get('phone'):
                    user_updates['phone'] = vals['phone']
                if user_updates:
                    enterprise.user_id.sudo().write(user_updates)
        
        return result
    
    # ==================== REGISTRATION APPROVAL ACTIONS ====================
    
    def action_approve_registration(self):
        """Approve enterprise registration - activates the user account"""
        self.ensure_one()
        if self.registration_status != 'pending':
            raise ValidationError(_('Seules les inscriptions en attente peuvent être approuvées.'))
        
        self.write({
            'registration_status': 'approved',
            'rejection_reason': False,
        })
        
        # Activate the user
        if self.user_id:
            self.user_id.sudo().write({'active': True})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Inscription Approuvée'),
                'message': _('L\'inscription de l\'entreprise %s a été approuvée. Le compte utilisateur est maintenant actif.') % self.name,
                'type': 'success',
                'sticky': False,
            }
        }
    
    def action_reject_registration(self):
        """Open wizard to reject enterprise registration with a reason"""
        self.ensure_one()
        if self.registration_status != 'pending':
            raise ValidationError(_('Seules les inscriptions en attente peuvent être rejetées.'))
        
        return {
            'name': _('Rejeter l\'inscription'),
            'type': 'ir.actions.act_window',
            'res_model': 'enterprise.reject.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_enterprise_id': self.id},
        }
    
    def action_set_pending(self):
        """Reset registration status to pending (for re-review)"""
        self.ensure_one()
        self.write({
            'registration_status': 'pending',
        })
        
        # Deactivate user until re-approved
        if self.user_id:
            self.user_id.sudo().write({'active': False})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Statut modifié'),
                'message': _('L\'inscription de %s est maintenant en attente de vérification.') % self.name,
                'type': 'warning',
                'sticky': False,
            }
        }
    
    def action_view_orders(self):
        """View orders for this enterprise"""
        self.ensure_one()
        return {
            'name': _('Commandes'),
            'type': 'ir.actions.act_window',
            'res_model': 'delivery.order',
            'view_mode': 'list,form',
            'domain': [
                '|',
                ('sender_id', '=', self.partner_id.id),
                ('sender_id.parent_id', '=', self.partner_id.id)
            ],
            'context': {'default_sender_id': self.partner_id.id},
        }
    
    def action_reset_password(self):
        """Send password reset email to enterprise"""
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
    
    @api.model
    def action_migrate_existing_users(self):
        """Migrate existing enterprise users that don't have a delivery.enterprise record"""
        import logging
        _logger = logging.getLogger(__name__)
        _logger.info("Starting enterprise user migration...")
        
        # Get the enterprise group
        enterprise_group = self.env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
        if not enterprise_group:
            _logger.error("Enterprise group not found!")
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Erreur'),
                    'message': _('Groupe entreprise non trouvé'),
                    'type': 'danger',
                }
            }
        
        # Get the admin group to exclude admins
        admin_group = self.env.ref('smart_delivery.group_admin', raise_if_not_found=False)
        livreur_group = self.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
        
        # Find all users with enterprise group
        enterprise_users = self.env['res.users'].sudo().search([
            ('groups_id', 'in', [enterprise_group.id]),
            ('active', 'in', [True, False]),
        ])
        
        _logger.info(f"Found {len(enterprise_users)} users with enterprise group")
        
        # Exclude admin users and livreurs
        if admin_group:
            enterprise_users = enterprise_users.filtered(lambda u: admin_group not in u.groups_id)
        if livreur_group:
            enterprise_users = enterprise_users.filtered(lambda u: livreur_group not in u.groups_id)
        
        _logger.info(f"After filtering admins/livreurs: {len(enterprise_users)} enterprise users")
        
        migrated_count = 0
        errors = []
        
        for user in enterprise_users:
            _logger.info(f"Processing user: {user.login}")
            
            # Check if this user already has an enterprise record
            existing_enterprise = self.sudo().search([('user_id', '=', user.id)], limit=1)
            if existing_enterprise:
                _logger.info(f"User {user.login} already has enterprise record")
                continue
            
            # Check if there's an enterprise with the same email
            email = user.email or user.login
            existing_by_email = self.sudo().search([('email', '=', email)], limit=1)
            if existing_by_email:
                existing_by_email.sudo().write({'user_id': user.id})
                _logger.info(f"Linked user {user.login} to existing enterprise")
                migrated_count += 1
                continue
            
            # Create a new enterprise record using ORM (skip user/partner creation)
            partner = user.partner_id
            try:
                # Direct SQL insert to avoid triggering create logic
                self.env.cr.execute("""
                    INSERT INTO delivery_enterprise 
                    (name, email, phone, user_id, partner_id, registration_status, 
                     create_uid, create_date, write_uid, write_date)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW() AT TIME ZONE 'UTC', %s, NOW() AT TIME ZONE 'UTC')
                """, (
                    partner.name if partner else user.name,
                    email,
                    partner.phone or user.phone or 'N/A',
                    user.id,
                    partner.id if partner else None,
                    'approved',
                    self.env.uid,
                    self.env.uid,
                ))
                migrated_count += 1
                _logger.info(f"Created enterprise record for user: {user.login}")
            except Exception as e:
                _logger.error(f"Error migrating user {user.login}: {e}")
                errors.append(f"{user.login}: {str(e)}")
                continue
        
        self.env.cr.commit()
        _logger.info(f"Migration complete: {migrated_count} created, {len(errors)} errors")
        
        message = _('%d entreprises migrées avec succès') % migrated_count
        if errors:
            message += _('\n\nErreurs: %s') % ', '.join(errors[:5])
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Migration terminée'),
                'message': message,
                'type': 'success' if not errors else 'warning',
            }
        }


class EnterpriseRejectWizard(models.TransientModel):
    _name = 'enterprise.reject.wizard'
    _description = 'Assistant de rejet d\'inscription entreprise'

    enterprise_id = fields.Many2one('delivery.enterprise', string='Entreprise', required=True, readonly=True)
    rejection_reason = fields.Text(string='Motif du rejet', required=True,
                                   help='Expliquez la raison du rejet de cette inscription')

    def action_confirm_reject(self):
        """Confirm the rejection with the provided reason"""
        self.ensure_one()
        
        if not self.rejection_reason:
            raise ValidationError(_('Veuillez indiquer le motif du rejet.'))
        
        self.enterprise_id.write({
            'registration_status': 'rejected',
            'rejection_reason': self.rejection_reason,
        })
        
        # Deactivate the user
        if self.enterprise_id.user_id:
            self.enterprise_id.user_id.sudo().write({'active': False})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Inscription Rejetée'),
                'message': _('L\'inscription de l\'entreprise %s a été rejetée.') % self.enterprise_id.name,
                'type': 'warning',
                'sticky': False,
            }
        }
