# -*- coding: utf-8 -*-

from odoo import models
from odoo.http import request


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _pre_dispatch(cls, rule, args):
        """Force debug mode for all requests"""
        result = super()._pre_dispatch(rule, args)
        
        # Set debug mode in session if not already set
        if request and hasattr(request, 'session'):
            request.session.debug = '1'
        
        return result
