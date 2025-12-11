# -*- coding: utf-8 -*-

import math
import random
import string
from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError


class DeliveryOrder(models.Model):
    _name = 'delivery.order'
    _description = 'Commande de Livraison'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'

    name = fields.Char(string='Référence', required=True, copy=False, readonly=True, default=lambda self: _('New'))
    reference = fields.Char(string='Référence Externe', tracking=True)
    sector_type = fields.Selection([
        ('standard', 'Standard'),
        ('premium', 'Premium'),
        ('express', 'Express'),
        ('fragile', 'Fragile'),
        ('medical', 'Médical'),
    ], string='Type de Secteur', required=True, tracking=True)
    
    @api.onchange('sector_type')
    def _onchange_sector_type(self):
        """Applique automatiquement les règles du secteur sélectionné"""
        if self.sector_type:
            sector_rule = self.env['sector.rule'].search([
                ('sector_type', '=', self.sector_type)
            ], limit=1)
            if sector_rule:
                self.otp_required = sector_rule.otp_required
                self.signature_required = sector_rule.signature_required
                self.photo_required = sector_rule.photo_required
                self.biometric_required = sector_rule.biometric_required
    
    sender_id = fields.Many2one('res.partner', string='Expéditeur', required=True, tracking=True)
    receiver_name = fields.Char(string='Nom du Destinataire', required=True, tracking=True)
    receiver_phone = fields.Char(string='Téléphone Destinataire', required=True, tracking=True)
    
    pickup_lat = fields.Float(string='Latitude Pickup', required=True, digits=(10, 7))
    pickup_long = fields.Float(string='Longitude Pickup', required=True, digits=(10, 7))
    drop_lat = fields.Float(string='Latitude Livraison', required=True, digits=(10, 7))
    drop_long = fields.Float(string='Longitude Livraison', required=True, digits=(10, 7))
    
    assigned_livreur_id = fields.Many2one('delivery.livreur', string='Livreur Assigné', tracking=True)
    
    status = fields.Selection([
        ('draft', 'Brouillon'),
        ('assigned', 'Assigné'),
        ('on_way', 'En Route'),
        ('delivered', 'Livré'),
        ('failed', 'Échoué'),
    ], string='Statut', default='draft', required=True, tracking=True)
    
    # Conditions de validation
    otp_required = fields.Boolean(string='OTP Requis', default=False)
    signature_required = fields.Boolean(string='Signature Requise', default=False)
    photo_required = fields.Boolean(string='Photo Requise', default=False)
    biometric_required = fields.Boolean(string='Biométrie Requise', default=False)
    
    # Relations
    condition_ids = fields.One2many('delivery.condition', 'order_id', string='Conditions')
    route_ids = fields.One2many('delivery.route', 'order_id', string='Itinéraire')
    billing_id = fields.One2many('delivery.billing', 'order_id', string='Facturation')
    
    # Champs calculés
    distance_km = fields.Float(string='Distance (km)', compute='_compute_distance', store=True)
    
    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self.env['ir.sequence'].next_by_code('delivery.order') or _('New')
            
            # Appliquer les règles du secteur
            if vals.get('sector_type'):
                sector_rule = self.env['sector.rule'].search([
                    ('sector_type', '=', vals['sector_type'])
                ], limit=1)
                if sector_rule:
                    vals.setdefault('otp_required', sector_rule.otp_required)
                    vals.setdefault('signature_required', sector_rule.signature_required)
                    vals.setdefault('photo_required', sector_rule.photo_required)
                    vals.setdefault('biometric_required', sector_rule.biometric_required)
        
        orders = super().create(vals_list)
        
        # Créer les conditions si nécessaire pour chaque commande
        for order in orders:
            if order.otp_required or order.signature_required or order.photo_required or order.biometric_required:
                condition_vals = {'order_id': order.id}
                # Générer OTP si requis
                if order.otp_required:
                    condition_vals['otp_value'] = ''.join(random.choices(string.digits, k=6))
                self.env['delivery.condition'].create(condition_vals)
        
        return orders
    
    @api.depends('pickup_lat', 'pickup_long', 'drop_lat', 'drop_long')
    def _compute_distance(self):
        for record in self:
            if record.pickup_lat and record.pickup_long and record.drop_lat and record.drop_long:
                record.distance_km = self._haversine_distance(
                    record.pickup_lat, record.pickup_long,
                    record.drop_lat, record.drop_long
                )
            else:
                record.distance_km = 0.0
    
    @staticmethod
    def _haversine_distance(lat1, lon1, lat2, lon2):
        """Calcule la distance en km entre deux points GPS"""
        R = 6371  # Rayon de la Terre en km
        
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def assign_livreur(self, force=False):
        """Moteur de dispatching automatique
        
        Args:
            force: Si True, écrase le livreur déjà assigné. Si False, garde le livreur existant.
        """
        self.ensure_one()
        
        if self.status != 'draft':
            raise UserError(_('Seules les commandes en brouillon peuvent être assignées'))
        
        # Si un livreur est déjà assigné et qu'on ne force pas, on le garde
        if self.assigned_livreur_id and not force:
            # Vérifier que le livreur est toujours disponible et vérifié
            if self.assigned_livreur_id.availability and self.assigned_livreur_id.verified:
                self.write({'status': 'assigned'})
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Livreur Confirmé'),
                        'message': _('Le livreur %s déjà assigné a été confirmé') % self.assigned_livreur_id.name,
                        'type': 'success',
                        'sticky': False,
                    }
                }
            else:
                # Le livreur assigné n'est plus disponible, on cherche un autre
                pass
        
        # Filtrer les livreurs disponibles
        available_livreurs = self.env['delivery.livreur'].search([
            ('availability', '=', True),
            ('verified', '=', True),
        ])
        
        if not available_livreurs:
            raise UserError(_('Aucun livreur disponible'))
        
        best_livreur = None
        best_score = -1
        
        for livreur in available_livreurs:
            # Calculer la distance du livreur au point de pickup
            distance = self._haversine_distance(
                livreur.current_lat, livreur.current_long,
                self.pickup_lat, self.pickup_long
            )
            
            # Normaliser la distance (0-1, plus petit = mieux)
            # On suppose une distance max de 50km
            distance_score = max(0, 1 - (distance / 50.0))
            
            # Score de notation (0-1)
            rating_score = livreur.rating / 5.0 if livreur.rating else 0.5
            
            # Temps de repos (simplifié - on suppose que tous sont reposés)
            rest_time_score = 1.0  # À améliorer avec un vrai calcul
            
            # Score de vitesse (basé sur le type de véhicule)
            speed_scores = {
                'motorcycle': 0.9,
                'car': 0.7,
                'bicycle': 0.5,
                'truck': 0.6,
            }
            speed_score = speed_scores.get(livreur.vehicle_type, 0.5)
            
            # Score final pondéré
            total_score = (
                distance_score * 0.50 +
                rating_score * 0.20 +
                rest_time_score * 0.10 +
                speed_score * 0.20
            )
            
            if total_score > best_score:
                best_score = total_score
                best_livreur = livreur
        
        if best_livreur:
            self.write({
                'assigned_livreur_id': best_livreur.id,
                'status': 'assigned',
            })
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Livreur Assigné'),
                    'message': _('Le livreur %s a été assigné avec un score de %.2f') % (best_livreur.name, best_score),
                    'type': 'success',
                    'sticky': False,
                }
            }
        else:
            raise UserError(_('Impossible de trouver un livreur approprié'))
    
    def validate_conditions(self):
        """Valide toutes les conditions requises pour la livraison"""
        self.ensure_one()
        
        condition = self.condition_ids[:1]
        if not condition:
            raise UserError(_('Aucune condition à valider'))
        
        errors = []
        
        # Valider OTP
        if self.otp_required:
            if not condition.otp_verified:
                errors.append(_('OTP non vérifié'))
        
        # Valider signature
        if self.signature_required:
            if not condition.signature_file:
                errors.append(_('Signature manquante'))
        
        # Valider photo
        if self.photo_required:
            if not condition.photo_url:
                errors.append(_('Photo manquante'))
        
        # Valider biométrie
        if self.biometric_required:
            if not condition.biometric_score or condition.biometric_score < 0.7:
                errors.append(_('Score biométrique insuffisant (minimum 0.7)'))
        
        if errors:
            raise ValidationError('\n'.join(errors))
        
        condition.write({'validated': True})
        self.write({'status': 'delivered'})
        
        # Générer la facturation
        self._generate_billing()
        
        return True
    
    def _generate_billing(self):
        """Génère la facturation pour la commande"""
        self.ensure_one()
        
        if self.billing_id:
            return self.billing_id[0]
        
        # Tarif de base selon le secteur
        base_tariffs = {
            'standard': 50.0,
            'premium': 100.0,
            'express': 150.0,
            'fragile': 120.0,
            'medical': 200.0,
        }
        base_tariff = base_tariffs.get(self.sector_type, 50.0)
        
        # Frais supplémentaires basés sur la distance
        extra_fee = max(0, (self.distance_km - 5) * 10)  # 10 par km au-delà de 5km
        
        total_amount = base_tariff + extra_fee
        commission = total_amount * 0.15  # 15% de commission
        
        billing = self.env['delivery.billing'].create({
            'order_id': self.id,
            'distance_km': self.distance_km,
            'base_tariff': base_tariff,
            'extra_fee': extra_fee,
            'total_amount': total_amount,
            'commission': commission,
        })
        
        return billing
    
    def action_start_delivery(self):
        """Démarre la livraison"""
        self.ensure_one()
        if self.status != 'assigned':
            raise UserError(_('La commande doit être assignée'))
        self.write({'status': 'on_way'})
    
    def action_fail_delivery(self):
        """Marque la livraison comme échouée"""
        self.ensure_one()
        self.write({'status': 'failed'})
    
    def action_view_conditions(self):
        """Ouvre la vue des conditions de la commande"""
        self.ensure_one()
        return {
            'name': _('Conditions'),
            'type': 'ir.actions.act_window',
            'res_model': 'delivery.condition',
            'view_mode': 'list,form',
            'domain': [('order_id', '=', self.id)],
            'context': {'default_order_id': self.id},
        }
    
    def action_view_billing(self):
        """Ouvre la vue de facturation de la commande"""
        self.ensure_one()
        return {
            'name': _('Facturation'),
            'type': 'ir.actions.act_window',
            'res_model': 'delivery.billing',
            'view_mode': 'list,form',
            'domain': [('order_id', '=', self.id)],
            'context': {'default_order_id': self.id},
        }

