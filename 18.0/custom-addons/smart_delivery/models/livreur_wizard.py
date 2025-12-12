# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class LivreurRejectWizard(models.TransientModel):
    _name = 'livreur.reject.wizard'
    _description = 'Assistant de rejet d\'inscription livreur'

    livreur_id = fields.Many2one('delivery.livreur', string='Livreur', required=True, readonly=True)
    rejection_reason = fields.Text(string='Motif du rejet', required=True,
                                   help='Expliquez la raison du rejet de cette inscription')

    def action_confirm_reject(self):
        """Confirm the rejection with the provided reason"""
        self.ensure_one()
        
        if not self.rejection_reason:
            raise ValidationError(_('Veuillez indiquer le motif du rejet.'))
        
        self.livreur_id.write({
            'registration_status': 'rejected',
            'rejection_reason': self.rejection_reason,
            'verified': False,
            'availability': False,
        })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Inscription Rejetée'),
                'message': _('L\'inscription du livreur %s a été rejetée.') % self.livreur_id.name,
                'type': 'warning',
                'sticky': False,
            }
        }
