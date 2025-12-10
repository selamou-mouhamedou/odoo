# -*- coding: utf-8 -*-

from odoo import models, fields, api
import json


class ApiLog(models.Model):
    _name = 'api.log'
    _description = 'Journal API'
    _order = 'create_date desc'

    client_id = fields.Char(string='ID Client', required=True)
    endpoint = fields.Char(string='Endpoint', required=True)
    payload = fields.Text(string='Payload')
    response = fields.Text(string='Réponse')
    created_at = fields.Datetime(string='Date de Création', default=fields.Datetime.now, readonly=True)
    
    status_code = fields.Integer(string='Code de Statut')
    error_message = fields.Text(string='Message d\'Erreur')
    
    def log_request(self, client_id, endpoint, payload, response, status_code=200, error_message=None):
        """Enregistre une requête API"""
        self.create({
            'client_id': client_id,
            'endpoint': endpoint,
            'payload': json.dumps(payload) if isinstance(payload, dict) else str(payload),
            'response': json.dumps(response) if isinstance(response, dict) else str(response),
            'status_code': status_code,
            'error_message': error_message,
        })

