# -*- coding: utf-8 -*-

import logging
from datetime import datetime, timedelta
from odoo import api, models
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)

# Try to import jwt, but make it optional
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    _logger.warning("PyJWT not installed. JWT authentication will not work. Install with: pip install PyJWT cryptography")


class JWTAuth:
    """JWT Authentication utilities"""
    
    # Secret key - In production, use a secure key from config
    SECRET_KEY = 'smart_delivery_secret_key_change_in_production'
    ALGORITHM = 'HS256'
    TOKEN_EXPIRY_HOURS = 24
    
    @classmethod
    def generate_token(cls, user_id, login):
        """Generate JWT token for a user"""
        if not JWT_AVAILABLE:
            raise ImportError("PyJWT is not installed. Please install it with: pip install PyJWT cryptography")
        try:
            payload = {
                'user_id': user_id,
                'login': login,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=cls.TOKEN_EXPIRY_HOURS),
            }
            token = jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
            return token
        except Exception as e:
            _logger.error(f"Error generating JWT token: {e}")
            raise
    
    @classmethod
    def verify_token(cls, token):
        """Verify and decode JWT token"""
        if not JWT_AVAILABLE:
            _logger.warning("PyJWT not available, cannot verify token")
            return None
        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            _logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            _logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            _logger.error(f"Error verifying JWT token: {e}")
            return None
    
    @classmethod
    def authenticate_user(cls, env, login, password):
        """Authenticate user and return user record"""
        try:
            # Use Odoo's proper authentication method (Odoo 18 style)
            from odoo import registry
            from odoo.exceptions import AccessDenied
            
            db = env.cr.dbname
            registry_instance = registry(db)
            
            # Odoo 18 uses credential dictionary format
            credential = {
                'login': login,
                'password': password,
                'type': 'password'
            }
            
            # Authenticate using Odoo's built-in method
            try:
                auth_info = registry_instance['res.users'].authenticate(
                    db, 
                    credential, 
                    {'interactive': False}
                )
                
                if auth_info and 'uid' in auth_info:
                    uid = auth_info['uid']
                    # Get the user record
                    user = env['res.users'].sudo().browse(uid)
                    if user.exists():
                        return user
            except AccessDenied:
                _logger.warning(f"Authentication failed for login: {login}")
                return None
            except Exception as e:
                _logger.error(f"Error during authentication: {e}", exc_info=True)
                return None
            
            return None
        except Exception as e:
            _logger.error(f"Error authenticating user: {e}", exc_info=True)
            return None
