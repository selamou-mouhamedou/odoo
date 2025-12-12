# -*- coding: utf-8 -*-

import json
import logging
from datetime import datetime, timedelta
from odoo import http, fields
from odoo.http import request
from odoo.exceptions import AccessDenied, ValidationError

_logger = logging.getLogger(__name__)

# Try to import JWT auth, but make it optional
try:
    from ..utils.jwt_auth import JWTAuth
    JWT_AVAILABLE = True
except ImportError as e:
    JWT_AVAILABLE = False
    _logger.warning(f"JWT authentication not available: {e}")
    # Create a dummy class to prevent errors
    class JWTAuth:
        @classmethod
        def generate_token(cls, *args, **kwargs):
            raise ImportError("PyJWT not installed")
        @classmethod
        def verify_token(cls, *args, **kwargs):
            return None
        @classmethod
        def authenticate_user(cls, *args, **kwargs):
            return None


class SmartDeliveryAPI(http.Controller):
    
    def _authenticate_jwt(self):
        """Authenticate request using JWT token"""
        if not JWT_AVAILABLE:
            return False
        try:
            auth_header = request.httprequest.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                payload = JWTAuth.verify_token(token)
                if payload:
                    user_id = payload.get('user_id')
                    # Set the user in the environment
                    user = request.env['res.users'].sudo().browse(user_id)
                    if user.exists():
                        # Store user_id for later use (don't change request.env to avoid permission issues)
                        request._jwt_user_id = user_id
                        request._jwt_user = user
                        # NOTE: Do NOT set request.session.uid - it causes session token validation errors
                        return True
        except Exception as e:
            _logger.error(f"JWT authentication error: {e}")
        return False
    
    def _authenticate(self):
        """Authenticate request via session or JWT"""
        # Check JWT authentication first (preferred for API)
        if self._authenticate_jwt():
            return True
        
        # Check session authentication as fallback
        try:
            if hasattr(request, 'session') and request.session and request.session.uid:
                return True
        except Exception:
            pass
        
        return False
    
    def _require_auth(self):
        """Require authentication, raise error if not authenticated"""
        if not self._authenticate():
            return request.make_response(
                json.dumps({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}),
                headers=[('Content-Type', 'application/json')],
                status=401
            )
        return None
    
    def _log_api_call(self, endpoint, payload, response, status_code=200, error=None):
        """Enregistre l'appel API"""
        client_id = request.httprequest.headers.get('X-Client-ID', 'unknown')
        try:
            request.env['api.log'].sudo().log_request(
                client_id=client_id,
                endpoint=endpoint,
                payload=payload,
                response=response,
                status_code=status_code,
                error_message=str(error) if error else None,
            )
        except Exception as e:
            _logger.error(f"Erreur lors de l'enregistrement du log API: {e}")
    
    def _json_response(self, data, status_code=200):
        """Retourne une réponse JSON"""
        response = request.make_response(
            json.dumps(data, default=str),
            headers=[('Content-Type', 'application/json')],
        )
        response.status_code = status_code
        return response
    
    def _get_user_type(self, user):
        """Get user type: 'admin', 'enterprise', 'livreur', or 'other'"""
        if not user:
            return 'other'
        
        # Check groups
        admin_group = request.env.ref('smart_delivery.group_admin', raise_if_not_found=False)
        enterprise_group = request.env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
        livreur_group = request.env.ref('smart_delivery.group_livreur', raise_if_not_found=False)
        
        if admin_group and admin_group.id in user.groups_id.ids:
            return 'admin'
        elif enterprise_group and enterprise_group.id in user.groups_id.ids:
            return 'enterprise'
        elif livreur_group and livreur_group.id in user.groups_id.ids:
            return 'livreur'
        
        # Fallback: check if user has a livreur record
        livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
        return 'livreur' if livreur else 'other'
    
    def _require_enterprise_or_admin(self):
        """Require that the authenticated user is enterprise or admin, return error response or user"""
        auth_error = self._require_auth()
        if auth_error:
            return None, auth_error
        
        user = self._get_current_user()
        if not user:
            error_response = self._json_response({
                'error': 'Utilisateur non trouvé après authentification',
                'code': 'USER_NOT_FOUND'
            }, 401)
            return None, error_response
        
        user_type = self._get_user_type(user)
        if user_type not in ('admin', 'enterprise'):
            error_response = self._json_response({
                'error': 'Accès refusé. Vous devez être une entreprise ou un administrateur.',
                'code': 'NOT_ENTERPRISE_OR_ADMIN',
                'user_type': user_type,
            }, 403)
            return None, error_response
        
        return user, None
    
    def _get_current_user(self):
        """Get current authenticated user"""
        # First check if we have a JWT authenticated user
        if hasattr(request, '_jwt_user') and request._jwt_user:
            return request._jwt_user
        
        if hasattr(request, '_jwt_user_id') and request._jwt_user_id:
            return request.env['res.users'].sudo().browse(request._jwt_user_id)
        
        # Check multiple sources for user ID (session, request.uid, or env.uid)
        uid = None
        if hasattr(request, 'session') and request.session.uid:
            uid = request.session.uid
        elif hasattr(request, 'uid') and request.uid:
            uid = request.uid
        elif hasattr(request, 'env') and request.env.uid:
            uid = request.env.uid
        
        if uid:
            return request.env['res.users'].sudo().browse(uid)
        return None
    
    def _get_current_livreur(self):
        """Get the livreur record linked to the current authenticated user"""
        user = self._get_current_user()
        if not user:
            return None
        livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
        return livreur if livreur.exists() else None
    
    def _require_livreur(self):
        """Require that the authenticated user is a livreur, return error response or livreur"""
        auth_error = self._require_auth()
        if auth_error:
            return None, auth_error
        
        # Get current user
        user = self._get_current_user()
        if not user:
            error_response = self._json_response({
                'error': 'Utilisateur non trouvé après authentification',
                'code': 'USER_NOT_FOUND'
            }, 401)
            return None, error_response
        
        # Find livreur linked to this user
        livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
        if not livreur:
            error_response = self._json_response({
                'error': 'Accès refusé. Vous devez être un livreur pour accéder à cette ressource.',
                'code': 'NOT_A_LIVREUR',
                'user_id': user.id,
                'user_login': user.login,
            }, 403)
            return None, error_response
        
        return livreur, None
    
    # ==================== AUTHENTICATION ENDPOINT ====================
    
    @http.route('/smart_delivery/api/auth/login', type='http', auth='public', methods=['POST'], csrf=False)
    def login(self, **kwargs):
        """
        POST /smart_delivery/api/auth/login - Authenticate user and get JWT token
        
        Request Body:
        {
            "login": "user@example.com",
            "password": "password123"
        }
        
        Response:
        {
            "success": true,
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "user": {
                "id": 1,
                "name": "User Name",
                "login": "user@example.com"
            },
            "expires_in": 86400
        }
        """
        if not JWT_AVAILABLE:
            return self._json_response({
                'error': 'JWT authentication not available. Please install PyJWT: pip install PyJWT cryptography',
                'code': 'JWT_NOT_AVAILABLE'
            }, 503)
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            # Accept both 'login' and 'Email' (case-insensitive)
            login = data.get('login') or data.get('Login') or data.get('email') or data.get('Email')
            password = data.get('password') or data.get('Password')
            
            if not login or not password:
                return self._json_response({
                    'error': 'login/email and password are required',
                    'code': 'MISSING_CREDENTIALS'
                }, 400)
            
            # Authenticate user - try with login first, then try with email if login fails
            user = JWTAuth.authenticate_user(request.env, login, password)
            
            # If authentication failed, try searching by email
            if not user:
                # Check if login might be an email and try to find user by email
                user_by_email = request.env['res.users'].sudo().search([
                    ('email', '=', login)
                ], limit=1)
                
                if user_by_email:
                    # Try authenticating with the user's actual login
                    user = JWTAuth.authenticate_user(request.env, user_by_email.login, password)
            
            if not user:
                return self._json_response({
                    'error': 'Invalid credentials',
                    'code': 'INVALID_CREDENTIALS'
                }, 401)
            
            # Generate JWT token
            token = JWTAuth.generate_token(user.id, user.login)
            
            # Get user type
            user_type = self._get_user_type(user)
            
            # Get livreur info if user is a livreur
            livreur_info = None
            if user_type == 'livreur':
                livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
                if livreur:
                    livreur_info = {
                        'id': livreur.id,
                        'name': livreur.name,
                        'phone': livreur.phone,
                        'vehicle_type': livreur.vehicle_type,
                        'availability': livreur.availability,
                        'registration_status': livreur.registration_status,
                        'verified': livreur.verified,
                        'nni': livreur.nni,
                    }
                    # If livreur is not approved, include rejection reason if rejected
                    if livreur.registration_status == 'rejected':
                        livreur_info['rejection_reason'] = livreur.rejection_reason
            
            # Get enterprise info if user is enterprise
            enterprise_info = None
            if user_type == 'enterprise':
                # First try to find delivery.enterprise record
                enterprise = request.env['delivery.enterprise'].sudo().search([('user_id', '=', user.id)], limit=1)
                if enterprise:
                    enterprise_info = {
                        'id': enterprise.id,
                        'name': enterprise.name,
                        'email': enterprise.email,
                        'phone': enterprise.phone,
                        'registration_status': enterprise.registration_status,
                        'partner_id': enterprise.partner_id.id if enterprise.partner_id else None,
                    }
                    if enterprise.registration_status == 'rejected':
                        enterprise_info['rejection_reason'] = enterprise.rejection_reason
                else:
                    # Fallback to partner info
                    partner = user.partner_id
                    if partner:
                        enterprise_info = {
                            'id': partner.id,
                            'name': partner.name,
                            'company_id': partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id,
                            'company_name': partner.commercial_partner_id.name if partner.commercial_partner_id else partner.name,
                            'registration_status': 'approved',  # Legacy enterprises are considered approved
                        }
            
            response_data = {
                'success': True,
                'token': token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'login': user.login,
                    'type': user_type,
                },
                'livreur': livreur_info,
                'enterprise': enterprise_info,
                'expires_in': JWTAuth.TOKEN_EXPIRY_HOURS * 3600,  # seconds
            }
            
            self._log_api_call('/smart_delivery/api/auth/login', {'login': login}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur login: {e}")
            error_response = {'error': str(e), 'code': 'LOGIN_ERROR'}
            self._log_api_call('/smart_delivery/api/auth/login', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/auth/logout', type='http', auth='public', methods=['POST'], csrf=False)
    def logout(self, **kwargs):
        """
        POST /smart_delivery/api/auth/logout - Logout user and invalidate session
        
        Headers:
            Authorization: Bearer <token>
        
        Response:
        {
            "success": true,
            "message": "Logged out successfully"
        }
        """
        try:
            # Check if user is authenticated
            auth_error = self._require_auth()
            if auth_error:
                return auth_error
            
            # Get current user info for logging
            user = self._get_current_user()
            user_info = {'id': user.id, 'login': user.login} if user else {}
            
            # Clear session if exists
            if hasattr(request, 'session') and request.session:
                try:
                    request.session.logout()
                except Exception as e:
                    _logger.debug(f"Session logout note: {e}")
            
            # Clear JWT user attributes from request
            if hasattr(request, '_jwt_user_id'):
                del request._jwt_user_id
            if hasattr(request, '_jwt_user'):
                del request._jwt_user
            
            response_data = {
                'success': True,
                'message': 'Logged out successfully',
            }
            
            self._log_api_call('/smart_delivery/api/auth/logout', user_info, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur logout: {e}")
            error_response = {'error': str(e), 'code': 'LOGOUT_ERROR'}
            self._log_api_call('/smart_delivery/api/auth/logout', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== LIVREUR REGISTRATION (NO AUTH REQUIRED) ====================
    
    @http.route('/smart_delivery/api/livreur/register', type='http', auth='public', methods=['POST'], csrf=False)
    def register_livreur(self, **kwargs):
        """
        POST /smart_delivery/api/livreur/register - Register a new livreur account (NO AUTH REQUIRED)
        
        This endpoint allows livreurs to create their own account from the mobile app.
        The account will be created with 'pending' status and needs admin approval.
        
        Request Body (multipart/form-data):
        {
            "name": "Nom du livreur",           # Required
            "phone": "+222XXXXXXXX",            # Required
            "email": "livreur@example.com",     # Required
            "password": "password123",          # Required (min 6 chars)
            "vehicle_type": "motorcycle",       # Required: motorcycle, car, bicycle, truck
            "nni": "1234567890",               # Required: Numéro National d'Identification
            "nni_photo": <file>,               # Required: Photo du NNI (base64 or file)
            "livreur_photo": <file>,           # Required: Photo d'identité du livreur
            "carte_grise_photo": <file>,       # Required: Photo de la carte grise
            "assurance_photo": <file>          # Required: Photo de l'assurance
        }
        
        Response (success):
        {
            "success": true,
            "message": "Inscription réussie. Votre compte est en attente de vérification.",
            "livreur": {
                "id": 1,
                "name": "Nom du livreur",
                "email": "livreur@example.com",
                "registration_status": "pending"
            }
        }
        
        Response (error):
        {
            "success": false,
            "error": "Description de l'erreur",
            "code": "ERROR_CODE"
        }
        """
        try:
            # Get data from request - support both JSON and multipart form data
            if request.httprequest.content_type and 'application/json' in request.httprequest.content_type:
                data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            else:
                # Multipart form data
                data = dict(request.httprequest.form)
            
            # Required fields validation
            required_fields = ['name', 'phone', 'email', 'password', 'vehicle_type', 'nni']
            missing_fields = [f for f in required_fields if not data.get(f)]
            
            if missing_fields:
                return self._json_response({
                    'success': False,
                    'error': f'Champs requis manquants: {", ".join(missing_fields)}',
                    'code': 'MISSING_FIELDS',
                    'missing_fields': missing_fields
                }, 400)
            
            # Validate email format
            email = data.get('email', '').strip()
            if '@' not in email or '.' not in email.split('@')[-1]:
                return self._json_response({
                    'success': False,
                    'error': 'Format email invalide',
                    'code': 'INVALID_EMAIL'
                }, 400)
            
            # Validate password length
            password = data.get('password', '')
            if len(password) < 6:
                return self._json_response({
                    'success': False,
                    'error': 'Le mot de passe doit contenir au moins 6 caractères',
                    'code': 'PASSWORD_TOO_SHORT'
                }, 400)
            
            # Validate vehicle type
            valid_vehicle_types = ['motorcycle', 'car', 'bicycle', 'truck']
            vehicle_type = data.get('vehicle_type', '').lower()
            if vehicle_type not in valid_vehicle_types:
                return self._json_response({
                    'success': False,
                    'error': f'Type de véhicule invalide. Valeurs acceptées: {", ".join(valid_vehicle_types)}',
                    'code': 'INVALID_VEHICLE_TYPE'
                }, 400)
            
            # Check if email already exists
            existing_livreur = request.env['delivery.livreur'].sudo().search([
                ('email', '=', email)
            ], limit=1)
            if existing_livreur:
                return self._json_response({
                    'success': False,
                    'error': 'Cet email est déjà utilisé par un autre livreur',
                    'code': 'EMAIL_EXISTS'
                }, 400)
            
            # Check if NNI already exists
            nni = data.get('nni', '').strip()
            existing_nni = request.env['delivery.livreur'].sudo().search([
                ('nni', '=', nni)
            ], limit=1)
            if existing_nni:
                return self._json_response({
                    'success': False,
                    'error': 'Ce NNI est déjà utilisé par un autre livreur',
                    'code': 'NNI_EXISTS'
                }, 400)
            
            # Check if user with this email/login already exists
            existing_user = request.env['res.users'].sudo().search([
                '|', ('login', '=', email), ('email', '=', email)
            ], limit=1)
            if existing_user:
                return self._json_response({
                    'success': False,
                    'error': 'Un compte utilisateur existe déjà avec cet email',
                    'code': 'USER_EXISTS'
                }, 400)
            
            # Process photo uploads
            photo_fields = ['nni_photo', 'livreur_photo', 'carte_grise_photo', 'assurance_photo']
            photos = {}
            
            for field in photo_fields:
                photo_data = None
                filename = None
                
                # Check for file upload in multipart form
                if field in request.httprequest.files:
                    file = request.httprequest.files[field]
                    if file and file.filename:
                        import base64
                        photo_data = base64.b64encode(file.read()).decode('utf-8')
                        filename = file.filename
                
                # Check for base64 data in JSON/form data
                elif data.get(field):
                    photo_data = data.get(field)
                    # If it already contains data: prefix, extract base64 part
                    if isinstance(photo_data, str) and 'base64,' in photo_data:
                        photo_data = photo_data.split('base64,')[1]
                    filename = data.get(f'{field}_filename', f'{field}.jpg')
                
                if not photo_data:
                    return self._json_response({
                        'success': False,
                        'error': f'Photo requise: {field}',
                        'code': 'MISSING_PHOTO',
                        'field': field
                    }, 400)
                
                photos[field] = photo_data
                photos[f'{field}_filename'] = filename
            
            # Create livreur record
            livreur_vals = {
                'name': data.get('name', '').strip(),
                'phone': data.get('phone', '').strip(),
                'email': email,
                'password': password,
                'vehicle_type': vehicle_type,
                'nni': nni,
                'nni_photo': photos.get('nni_photo'),
                'nni_photo_filename': photos.get('nni_photo_filename'),
                'livreur_photo': photos.get('livreur_photo'),
                'livreur_photo_filename': photos.get('livreur_photo_filename'),
                'carte_grise_photo': photos.get('carte_grise_photo'),
                'carte_grise_photo_filename': photos.get('carte_grise_photo_filename'),
                'assurance_photo': photos.get('assurance_photo'),
                'assurance_photo_filename': photos.get('assurance_photo_filename'),
                'registration_status': 'pending',
                'verified': False,
                'availability': False,  # Not available until approved
            }
            
            # Create the livreur (this will also create the user)
            livreur = request.env['delivery.livreur'].sudo().create(livreur_vals)
            
            response_data = {
                'success': True,
                'message': 'Inscription réussie. Votre compte est en attente de vérification par un administrateur.',
                'livreur': {
                    'id': livreur.id,
                    'name': livreur.name,
                    'email': livreur.email,
                    'phone': livreur.phone,
                    'vehicle_type': livreur.vehicle_type,
                    'registration_status': livreur.registration_status,
                }
            }
            
            self._log_api_call('/smart_delivery/api/livreur/register', 
                             {'name': data.get('name'), 'email': email, 'phone': data.get('phone')}, 
                             response_data)
            return self._json_response(response_data, 201)
            
        except ValidationError as e:
            _logger.error(f"Validation error during livreur registration: {e}")
            error_response = {
                'success': False,
                'error': str(e),
                'code': 'VALIDATION_ERROR'
            }
            self._log_api_call('/smart_delivery/api/livreur/register', data if 'data' in dir() else {}, 
                             error_response, 400, e)
            return self._json_response(error_response, 400)
            
        except Exception as e:
            _logger.error(f"Error during livreur registration: {e}")
            error_response = {
                'success': False,
                'error': str(e),
                'code': 'REGISTRATION_ERROR'
            }
            self._log_api_call('/smart_delivery/api/livreur/register', data if 'data' in dir() else {}, 
                             error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== ENTERPRISE REGISTRATION (NO AUTH REQUIRED) ====================
    
    @http.route('/smart_delivery/api/enterprise/register', type='http', auth='public', methods=['POST'], csrf=False)
    def register_enterprise(self, **kwargs):
        """
        POST /smart_delivery/api/enterprise/register - Register a new enterprise account (NO AUTH REQUIRED)
        
        This endpoint allows enterprises to create their own account from web/mobile app.
        The account will be created with 'pending' status and needs admin approval.
        
        Request Body (multipart/form-data or JSON):
        {
            "name": "Nom de l'entreprise",       # Required
            "email": "contact@entreprise.com",   # Required
            "phone": "+222XXXXXXXX",             # Required
            "password": "password123",           # Required (min 6 chars)
            "logo": <file or base64>,            # Optional: Logo de l'entreprise
            "address": "Adresse complète",       # Optional
            "city": "Ville",                     # Optional
            "website": "https://...",            # Optional
            "description": "Description..."      # Optional
        }
        
        Response (success):
        {
            "success": true,
            "message": "Inscription réussie. Votre compte est en attente de vérification.",
            "enterprise": {
                "id": 1,
                "name": "Nom de l'entreprise",
                "email": "contact@entreprise.com",
                "registration_status": "pending"
            }
        }
        """
        try:
            # Get data from request - support both JSON and multipart form data
            if request.httprequest.content_type and 'application/json' in request.httprequest.content_type:
                data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            else:
                # Multipart form data
                data = dict(request.httprequest.form)
            
            # Required fields validation
            required_fields = ['name', 'email', 'phone', 'password']
            missing_fields = [f for f in required_fields if not data.get(f)]
            
            if missing_fields:
                return self._json_response({
                    'success': False,
                    'error': f'Champs requis manquants: {", ".join(missing_fields)}',
                    'code': 'MISSING_FIELDS',
                    'missing_fields': missing_fields
                }, 400)
            
            # Validate email format
            email = data.get('email', '').strip()
            if '@' not in email or '.' not in email.split('@')[-1]:
                return self._json_response({
                    'success': False,
                    'error': 'Format email invalide',
                    'code': 'INVALID_EMAIL'
                }, 400)
            
            # Validate password length
            password = data.get('password', '')
            if len(password) < 6:
                return self._json_response({
                    'success': False,
                    'error': 'Le mot de passe doit contenir au moins 6 caractères',
                    'code': 'PASSWORD_TOO_SHORT'
                }, 400)
            
            # Check if email already exists in enterprise
            existing_enterprise = request.env['delivery.enterprise'].sudo().search([
                ('email', '=', email)
            ], limit=1)
            if existing_enterprise:
                return self._json_response({
                    'success': False,
                    'error': 'Cet email est déjà utilisé par une autre entreprise',
                    'code': 'EMAIL_EXISTS'
                }, 400)
            
            # Check if user with this email/login already exists
            existing_user = request.env['res.users'].sudo().search([
                '|', ('login', '=', email), ('email', '=', email)
            ], limit=1)
            if existing_user:
                return self._json_response({
                    'success': False,
                    'error': 'Un compte utilisateur existe déjà avec cet email',
                    'code': 'USER_EXISTS'
                }, 400)
            
            # Process logo if provided
            logo_data = None
            logo_filename = None
            
            # Check for file upload in multipart form
            if 'logo' in request.httprequest.files:
                file = request.httprequest.files['logo']
                if file and file.filename:
                    import base64
                    logo_data = base64.b64encode(file.read()).decode('utf-8')
                    logo_filename = file.filename
            
            # Check for base64 data in JSON/form data
            elif data.get('logo'):
                logo_data = data.get('logo')
                # If it already contains data: prefix, extract base64 part
                if isinstance(logo_data, str) and 'base64,' in logo_data:
                    logo_data = logo_data.split('base64,')[1]
                logo_filename = data.get('logo_filename', 'logo.png')
            
            # Create enterprise record
            enterprise_vals = {
                'name': data.get('name', '').strip(),
                'email': email,
                'phone': data.get('phone', '').strip(),
                'password': password,
                'logo': logo_data,
                'logo_filename': logo_filename,
                'address': data.get('address', '').strip() if data.get('address') else None,
                'city': data.get('city', '').strip() if data.get('city') else None,
                'website': data.get('website', '').strip() if data.get('website') else None,
                'description': data.get('description', '').strip() if data.get('description') else None,
                'registration_status': 'pending',
            }
            
            # Create the enterprise (this will also create the partner and user)
            enterprise = request.env['delivery.enterprise'].sudo().create(enterprise_vals)
            
            response_data = {
                'success': True,
                'message': 'Inscription réussie. Votre compte est en attente de vérification par un administrateur.',
                'enterprise': {
                    'id': enterprise.id,
                    'name': enterprise.name,
                    'email': enterprise.email,
                    'phone': enterprise.phone,
                    'registration_status': enterprise.registration_status,
                }
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/register', 
                             {'name': data.get('name'), 'email': email, 'phone': data.get('phone')}, 
                             response_data)
            return self._json_response(response_data, 201)
            
        except ValidationError as e:
            _logger.error(f"Validation error during enterprise registration: {e}")
            error_response = {
                'success': False,
                'error': str(e),
                'code': 'VALIDATION_ERROR'
            }
            self._log_api_call('/smart_delivery/api/enterprise/register', data if 'data' in dir() else {}, 
                             error_response, 400, e)
            return self._json_response(error_response, 400)
            
        except Exception as e:
            _logger.error(f"Error during enterprise registration: {e}")
            error_response = {
                'success': False,
                'error': str(e),
                'code': 'REGISTRATION_ERROR'
            }
            self._log_api_call('/smart_delivery/api/enterprise/register', data if 'data' in dir() else {}, 
                             error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== SWAGGER DOCUMENTATION ====================
    
    @http.route('/smart_delivery/api/docs', type='http', auth='public', methods=['GET'], csrf=False)
    def swagger_docs(self, **kwargs):
        """GET /smart_delivery/api/docs - Swagger/OpenAPI documentation"""
        try:
            swagger_spec = self._get_swagger_spec()
            return request.make_response(
                json.dumps(swagger_spec, indent=2),
                headers=[('Content-Type', 'application/json')]
            )
        except Exception as e:
            _logger.error(f"Swagger docs error: {e}")
            return request.make_response(
                json.dumps({'error': str(e)}),
                headers=[('Content-Type', 'application/json')]
            )
    
    @http.route('/smart_delivery/api/docs/ui', type='http', auth='public', methods=['GET'], csrf=False)
    def swagger_ui(self, **kwargs):
        """GET /smart_delivery/api/docs/ui - Swagger UI HTML page"""
        try:
            html = """
<!DOCTYPE html>
<html>
<head>
    <title>Smart Delivery API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/smart_delivery/api/docs',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
            """
            return request.make_response(html, headers=[('Content-Type', 'text/html')])
        except Exception as e:
            _logger.error(f"Swagger UI error: {e}")
            return request.make_response(f"Error: {e}", headers=[('Content-Type', 'text/plain')])
    
    def _get_swagger_spec(self):
        """Generate OpenAPI 3.0 specification"""
        base_url = request.httprequest.host_url.rstrip('/')
        
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Smart Delivery API",
                "description": """
# Smart Delivery API

API pour la gestion des livraisons avec trois types d'utilisateurs:

## Types d'utilisateurs

| Type | Accès |
|------|-------|
| **Admin** | Accès complet à toutes les fonctionnalités |
| **Enterprise** | Gestion des commandes de leur entreprise, recherche de livreurs par secteur |
| **Livreur** | API mobile pour gérer leurs livraisons assignées |

## Authentification

Toutes les requêtes (sauf login) nécessitent un token JWT dans le header:
```
Authorization: Bearer <token>
```
                """,
                "version": "2.0.0",
                "contact": {
                    "name": "Smart Delivery Team"
                }
            },
            "servers": [{"url": base_url, "description": "Odoo Server"}],
            "tags": [
                {"name": "1. Authentication", "description": "Authentification et gestion de session"},
                {"name": "2. Enterprise - Orders", "description": "Gestion des commandes pour les entreprises"},
                {"name": "3. Enterprise - Sectors", "description": "Recherche de livreurs par secteur"},
                {"name": "4. Enterprise - Billing", "description": "Facturation et statistiques entreprise"},
                {"name": "5. Driver - Orders", "description": "Gestion des commandes pour les livreurs"},
                {"name": "6. Driver - Delivery", "description": "Processus de livraison"},
                {"name": "7. Driver - Profile", "description": "Profil et localisation du livreur"},
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                        "description": "Token JWT obtenu via /smart_delivery/api/auth/login"
                    }
                },
                "schemas": {
                    "Error": {
                        "type": "object",
                        "properties": {
                            "error": {"type": "string"},
                            "code": {"type": "string"}
                        }
                    },
                    "SectorType": {
                        "type": "string",
                        "enum": ["standard", "premium", "express", "fragile", "medical"],
                        "description": "Type de secteur de livraison"
                    }
                },
                "responses": {
                    "BadRequest": {"description": "Requête invalide", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "Unauthorized": {"description": "Non authentifié", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "Forbidden": {"description": "Accès refusé", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "NotFound": {"description": "Ressource non trouvée", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
                }
            },
            "paths": {
                # ==================== AUTHENTICATION ====================
                "/smart_delivery/api/auth/login": {
                    "post": {
                        "tags": ["1. Authentication"],
                        "summary": "Connexion et obtention du token JWT",
                        "description": "Authentifie l'utilisateur et retourne un token JWT. Le type d'utilisateur (admin/enterprise/livreur) est inclus dans la réponse.",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["login", "password"],
                                        "properties": {
                                            "login": {"type": "string", "example": "user@example.com"},
                                            "password": {"type": "string", "format": "password"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Connexion réussie",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "token": {"type": "string"},
                                                "user": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"},
                                                        "login": {"type": "string"},
                                                        "type": {"type": "string", "enum": ["admin", "enterprise", "livreur", "other"]}
                                                    }
                                                },
                                                "expires_in": {"type": "integer", "description": "Durée de validité en secondes"}
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/auth/logout": {
                    "post": {
                        "tags": ["1. Authentication"],
                        "summary": "Déconnexion",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Déconnexion réussie"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/register": {
                    "post": {
                        "tags": ["1. Authentication"],
                        "summary": "Inscription livreur (sans authentification)",
                        "description": """Permet aux livreurs de créer leur compte depuis l'application mobile.
                        
**Aucune authentification requise.**

Le compte sera créé avec le statut 'pending' (en attente) et nécessite une approbation par un administrateur.

Les photos peuvent être envoyées en base64 ou en fichiers via multipart/form-data.""",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "phone", "email", "password", "vehicle_type", "nni", "nni_photo", "livreur_photo", "carte_grise_photo", "assurance_photo"],
                                        "properties": {
                                            "name": {"type": "string", "description": "Nom complet du livreur", "example": "Mohamed Diallo"},
                                            "phone": {"type": "string", "description": "Numéro de téléphone", "example": "+22212345678"},
                                            "email": {"type": "string", "format": "email", "description": "Email (sera utilisé comme identifiant)", "example": "mohamed@example.com"},
                                            "password": {"type": "string", "format": "password", "minLength": 6, "description": "Mot de passe (min 6 caractères)"},
                                            "vehicle_type": {"type": "string", "enum": ["motorcycle", "car", "bicycle", "truck"], "description": "Type de véhicule"},
                                            "nni": {"type": "string", "description": "Numéro National d'Identification", "example": "1234567890"},
                                            "nni_photo": {"type": "string", "format": "binary", "description": "Photo du document NNI"},
                                            "livreur_photo": {"type": "string", "format": "binary", "description": "Photo d'identité du livreur"},
                                            "carte_grise_photo": {"type": "string", "format": "binary", "description": "Photo de la carte grise du véhicule"},
                                            "assurance_photo": {"type": "string", "format": "binary", "description": "Photo du document d'assurance"}
                                        }
                                    }
                                },
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "phone", "email", "password", "vehicle_type", "nni", "nni_photo", "livreur_photo", "carte_grise_photo", "assurance_photo"],
                                        "properties": {
                                            "name": {"type": "string", "example": "Mohamed Diallo"},
                                            "phone": {"type": "string", "example": "+22212345678"},
                                            "email": {"type": "string", "format": "email", "example": "mohamed@example.com"},
                                            "password": {"type": "string", "format": "password"},
                                            "vehicle_type": {"type": "string", "enum": ["motorcycle", "car", "bicycle", "truck"]},
                                            "nni": {"type": "string", "example": "1234567890"},
                                            "nni_photo": {"type": "string", "description": "Photo NNI en base64"},
                                            "livreur_photo": {"type": "string", "description": "Photo livreur en base64"},
                                            "carte_grise_photo": {"type": "string", "description": "Photo carte grise en base64"},
                                            "assurance_photo": {"type": "string", "description": "Photo assurance en base64"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "Inscription réussie",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": True},
                                                "message": {"type": "string", "example": "Inscription réussie. Votre compte est en attente de vérification."},
                                                "livreur": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"},
                                                        "email": {"type": "string"},
                                                        "phone": {"type": "string"},
                                                        "vehicle_type": {"type": "string"},
                                                        "registration_status": {"type": "string", "enum": ["pending", "approved", "rejected"]}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Erreur de validation",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": False},
                                                "error": {"type": "string"},
                                                "code": {"type": "string", "enum": ["MISSING_FIELDS", "INVALID_EMAIL", "PASSWORD_TOO_SHORT", "INVALID_VEHICLE_TYPE", "EMAIL_EXISTS", "NNI_EXISTS", "USER_EXISTS", "MISSING_PHOTO"]}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/smart_delivery/api/enterprise/register": {
                    "post": {
                        "tags": ["1. Authentication"],
                        "summary": "Inscription entreprise (sans authentification)",
                        "description": """Permet aux entreprises de créer leur compte depuis le web ou l'application mobile.
                        
**Aucune authentification requise.**

Le compte sera créé avec le statut 'pending' (en attente) et nécessite une approbation par un administrateur.

Le logo peut être envoyé en base64 ou en fichier via multipart/form-data.""",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "email", "phone", "password"],
                                        "properties": {
                                            "name": {"type": "string", "description": "Nom de l'entreprise", "example": "Transport Express SARL"},
                                            "email": {"type": "string", "format": "email", "description": "Email (sera utilisé comme identifiant)", "example": "contact@transport-express.mr"},
                                            "phone": {"type": "string", "description": "Numéro de téléphone", "example": "+22212345678"},
                                            "password": {"type": "string", "format": "password", "minLength": 6, "description": "Mot de passe (min 6 caractères)"},
                                            "logo": {"type": "string", "format": "binary", "description": "Logo de l'entreprise (optionnel)"},
                                            "address": {"type": "string", "description": "Adresse complète (optionnel)"},
                                            "city": {"type": "string", "description": "Ville (optionnel)", "example": "Nouakchott"},
                                            "website": {"type": "string", "description": "Site web (optionnel)", "example": "https://transport-express.mr"},
                                            "description": {"type": "string", "description": "Description de l'activité (optionnel)"}
                                        }
                                    }
                                },
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "email", "phone", "password"],
                                        "properties": {
                                            "name": {"type": "string", "example": "Transport Express SARL"},
                                            "email": {"type": "string", "format": "email", "example": "contact@transport-express.mr"},
                                            "phone": {"type": "string", "example": "+22212345678"},
                                            "password": {"type": "string", "format": "password"},
                                            "logo": {"type": "string", "description": "Logo en base64 (optionnel)"},
                                            "address": {"type": "string"},
                                            "city": {"type": "string"},
                                            "website": {"type": "string"},
                                            "description": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "Inscription réussie",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": True},
                                                "message": {"type": "string", "example": "Inscription réussie. Votre compte est en attente de vérification."},
                                                "enterprise": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"},
                                                        "email": {"type": "string"},
                                                        "phone": {"type": "string"},
                                                        "registration_status": {"type": "string", "enum": ["pending", "approved", "rejected"]}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Erreur de validation",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": False},
                                                "error": {"type": "string"},
                                                "code": {"type": "string", "enum": ["MISSING_FIELDS", "INVALID_EMAIL", "PASSWORD_TOO_SHORT", "EMAIL_EXISTS", "USER_EXISTS"]}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/smart_delivery/api/user/info": {
                    "get": {
                        "tags": ["1. Authentication"],
                        "summary": "Obtenir les informations de l'utilisateur connecté",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Informations utilisateur"}
                        }
                    }
                },
                
                # ==================== ENTERPRISE - ORDERS ====================
                "/smart_delivery/api/delivery/create": {
                    "post": {
                        "tags": ["2. Enterprise - Orders"],
                        "summary": "Créer une nouvelle commande",
                        "description": "Crée une commande de livraison. Pour les entreprises, le sender_id est automatiquement défini sur leur société.",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["sector_type", "receiver_name", "receiver_phone", "pickup_lat", "pickup_long", "drop_lat", "drop_long"],
                                        "properties": {
                                            "reference": {"type": "string", "description": "Référence externe"},
                                            "sector_type": {"$ref": "#/components/schemas/SectorType"},
                                            "sender_id": {"type": "integer", "description": "ID du partenaire expéditeur (auto pour enterprise)"},
                                            "receiver_name": {"type": "string"},
                                            "receiver_phone": {"type": "string"},
                                            "pickup_lat": {"type": "number"},
                                            "pickup_long": {"type": "number"},
                                            "drop_lat": {"type": "number"},
                                            "drop_long": {"type": "number"},
                                            "livreur_id": {"type": "integer", "description": "ID du livreur à assigner (optionnel)"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Commande créée"},
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "403": {"$ref": "#/components/responses/Forbidden"}
                        }
                    }
                },
                "/smart_delivery/api/enterprise/my-orders": {
                    "get": {
                        "tags": ["2. Enterprise - Orders"],
                        "summary": "Lister mes commandes",
                        "description": "Retourne toutes les commandes de l'entreprise connectée.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "status", "in": "query", "schema": {"$ref": "#/components/schemas/SectorType"}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                        ],
                        "responses": {
                            "200": {"description": "Liste des commandes"},
                            "403": {"$ref": "#/components/responses/Forbidden"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/status/{order_id}": {
                    "get": {
                        "tags": ["2. Enterprise - Orders"],
                        "summary": "Obtenir le statut d'une commande",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Statut de la commande"},
                            "403": {"$ref": "#/components/responses/Forbidden"},
                            "404": {"$ref": "#/components/responses/NotFound"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/assign": {
                    "post": {
                        "tags": ["2. Enterprise - Orders"],
                        "summary": "Assigner un livreur à une commande",
                        "description": "Déclenche le dispatching automatique ou confirme le livreur assigné.",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["order_id"],
                                        "properties": {
                                            "order_id": {"type": "integer"},
                                            "force": {"type": "boolean", "default": False, "description": "Forcer le re-dispatching"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Livreur assigné"}
                        }
                    }
                },
                
                # ==================== ENTERPRISE - SECTORS ====================
                "/smart_delivery/api/enterprise/sectors": {
                    "get": {
                        "tags": ["3. Enterprise - Sectors"],
                        "summary": "Lister tous les secteurs disponibles",
                        "description": "Retourne la liste des secteurs avec leurs exigences et le nombre de livreurs.",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Liste des secteurs",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "sectors": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id": {"type": "integer"},
                                                            "sector_type": {"$ref": "#/components/schemas/SectorType"},
                                                            "description": {"type": "string"},
                                                            "requirements": {
                                                                "type": "object",
                                                                "properties": {
                                                                    "otp_required": {"type": "boolean"},
                                                                    "signature_required": {"type": "boolean"},
                                                                    "photo_required": {"type": "boolean"},
                                                                    "biometric_required": {"type": "boolean"}
                                                                }
                                                            },
                                                            "livreur_count": {"type": "integer"}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/smart_delivery/api/enterprise/livreurs-by-sector": {
                    "get": {
                        "tags": ["3. Enterprise - Sectors"],
                        "summary": "Trouver des livreurs par secteur",
                        "description": "Retourne les livreurs qui travaillent dans un secteur donné.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "sector", "in": "query", "required": True, "schema": {"$ref": "#/components/schemas/SectorType"}, "description": "Code du secteur"},
                            {"name": "available_only", "in": "query", "schema": {"type": "boolean", "default": True}, "description": "Filtrer les livreurs disponibles"},
                            {"name": "verified_only", "in": "query", "schema": {"type": "boolean", "default": False}, "description": "Filtrer les livreurs vérifiés"},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                        ],
                        "responses": {
                            "200": {
                                "description": "Liste des livreurs",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "sector": {"type": "object"},
                                                "livreurs_count": {"type": "integer"},
                                                "livreurs": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id": {"type": "integer"},
                                                            "name": {"type": "string"},
                                                            "phone": {"type": "string"},
                                                            "vehicle_type": {"type": "string"},
                                                            "availability": {"type": "boolean"},
                                                            "verified": {"type": "boolean"},
                                                            "rating": {"type": "number"},
                                                            "sectors": {"type": "array", "items": {"type": "string"}}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {"$ref": "#/components/responses/BadRequest"}
                        }
                    }
                },
                
                # ==================== ENTERPRISE - BILLING ====================
                "/smart_delivery/api/enterprise/my-billings": {
                    "get": {
                        "tags": ["4. Enterprise - Billing"],
                        "summary": "Lister mes factures",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "state", "in": "query", "schema": {"type": "string", "enum": ["draft", "confirmed", "paid", "cancelled"]}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                        ],
                        "responses": {
                            "200": {"description": "Liste des factures"}
                        }
                    }
                },
                "/smart_delivery/api/enterprise/stats": {
                    "get": {
                        "tags": ["4. Enterprise - Billing"],
                        "summary": "Obtenir les statistiques de l'entreprise",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Statistiques",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "stats": {
                                                    "type": "object",
                                                    "properties": {
                                                        "total_orders": {"type": "integer"},
                                                        "delivered": {"type": "integer"},
                                                        "in_progress": {"type": "integer"},
                                                        "failed": {"type": "integer"},
                                                        "total_spent": {"type": "number"},
                                                        "total_paid": {"type": "number"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                
                # ==================== DRIVER - ORDERS ====================
                "/smart_delivery/api/livreur/my-orders": {
                    "get": {
                        "tags": ["5. Driver - Orders"],
                        "summary": "Lister mes commandes assignées",
                        "description": "Retourne toutes les commandes assignées au livreur connecté.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["draft", "assigned", "on_way", "delivered", "failed"]}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                        ],
                        "responses": {
                            "200": {"description": "Liste des commandes"},
                            "403": {"description": "Pas un livreur"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/orders/{order_id}/details": {
                    "get": {
                        "tags": ["5. Driver - Orders"],
                        "summary": "Détails complets d'une commande",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Détails de la commande"},
                            "403": {"description": "Commande non assignée à ce livreur"},
                            "404": {"$ref": "#/components/responses/NotFound"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/orders/{order_id}/otp": {
                    "get": {
                        "tags": ["5. Driver - Orders"],
                        "summary": "Obtenir l'OTP d'une commande",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Code OTP"},
                            "403": {"description": "Commande non assignée à ce livreur"}
                        }
                    }
                },
                
                # ==================== DRIVER - DELIVERY ====================
                "/smart_delivery/api/livreur/orders/{order_id}/start": {
                    "post": {
                        "tags": ["6. Driver - Delivery"],
                        "summary": "Démarrer une livraison",
                        "description": "Change le statut de 'assigned' à 'on_way'.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Livraison démarrée"},
                            "400": {"description": "Statut invalide"},
                            "403": {"description": "Commande non assignée à ce livreur"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/orders/{order_id}/deliver": {
                    "post": {
                        "tags": ["6. Driver - Delivery"],
                        "summary": "Valider et terminer une livraison",
                        "description": "Valide les conditions (OTP, signature, photo, biométrie) selon les exigences et marque la commande comme livrée.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "otp_value": {"type": "string", "description": "Code OTP (si requis)"},
                                            "signature": {"type": "string", "format": "base64", "description": "Signature en base64 (si requise)"},
                                            "photo_url": {"type": "string", "format": "uri", "description": "URL de la photo (si requise)"},
                                            "biometric_score": {"type": "number", "minimum": 0, "maximum": 1, "description": "Score biométrique min 0.7 (si requis)"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Livraison validée avec succès"},
                            "400": {"description": "Validation échouée"}
                        }
                    }
                },
                
                # ==================== DRIVER - PROFILE ====================
                "/smart_delivery/api/livreur/location": {
                    "post": {
                        "tags": ["7. Driver - Profile"],
                        "summary": "Mettre à jour ma position GPS",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["lat", "long"],
                                        "properties": {
                                            "lat": {"type": "number", "example": 33.5731},
                                            "long": {"type": "number", "example": -7.5898}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Position mise à jour"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/stats": {
                    "get": {
                        "tags": ["7. Driver - Profile"],
                        "summary": "Obtenir mes statistiques",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Statistiques du livreur",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "stats": {
                                                    "type": "object",
                                                    "properties": {
                                                        "today": {"type": "integer"},
                                                        "in_progress": {"type": "integer"},
                                                        "delivered": {"type": "integer"},
                                                        "failed": {"type": "integer"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/smart_delivery/api/livreur/change-password": {
                    "post": {
                        "tags": ["7. Driver - Profile"],
                        "summary": "Changer mon mot de passe",
                        "description": "Permet au livreur de changer son mot de passe. Nécessite le mot de passe actuel pour validation.",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["current_password", "new_password"],
                                        "properties": {
                                            "current_password": {"type": "string", "format": "password", "description": "Mot de passe actuel"},
                                            "new_password": {"type": "string", "format": "password", "minLength": 6, "description": "Nouveau mot de passe (min 6 caractères)"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Mot de passe modifié avec succès",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": True},
                                                "message": {"type": "string", "example": "Mot de passe modifié avec succès"}
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Erreur de validation",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": False},
                                                "error": {"type": "string"},
                                                "code": {"type": "string", "enum": ["MISSING_FIELDS", "PASSWORD_TOO_SHORT"]}
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {
                                "description": "Mot de passe actuel incorrect",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": False},
                                                "error": {"type": "string"},
                                                "code": {"type": "string", "example": "INVALID_CURRENT_PASSWORD"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/smart_delivery/api/livreur/update-profile": {
                    "post": {
                        "tags": ["7. Driver - Profile"],
                        "summary": "Mettre à jour mon profil",
                        "description": "Permet au livreur de modifier son nom et/ou sa photo de profil. Au moins un champ doit être fourni.",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "description": "Nouveau nom du livreur"},
                                            "livreur_photo": {"type": "string", "format": "binary", "description": "Nouvelle photo du livreur"}
                                        }
                                    }
                                },
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "description": "Nouveau nom du livreur"},
                                            "livreur_photo": {"type": "string", "description": "Photo en base64"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Profil mis à jour avec succès",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": True},
                                                "message": {"type": "string", "example": "Profil mis à jour avec succès"},
                                                "livreur": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"},
                                                        "has_photo": {"type": "boolean"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Erreur de validation",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean", "example": False},
                                                "error": {"type": "string"},
                                                "code": {"type": "string", "example": "NO_FIELDS_PROVIDED"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    
    # ==================== DEBUG ENDPOINT ====================
    
    @http.route('/smart_delivery/api/debug/auth', type='http', auth='public', methods=['GET'], csrf=False)
    def debug_auth(self, **kwargs):
        """Debug endpoint to check authentication status"""
        try:
            result = {
                'jwt_available': JWT_AVAILABLE,
                'has_auth_header': bool(request.httprequest.headers.get('Authorization')),
            }
            
            # Try to authenticate
            auth_result = self._authenticate()
            result['authenticated'] = auth_result
            
            # Check JWT user
            if hasattr(request, '_jwt_user_id'):
                result['jwt_user_id'] = request._jwt_user_id
            if hasattr(request, '_jwt_user'):
                result['jwt_user_exists'] = bool(request._jwt_user)
            
            # Get current user
            user = self._get_current_user()
            if user:
                result['current_user'] = {
                    'id': user.id,
                    'name': user.name,
                    'login': user.login,
                }
                
                # Check if user has livreur
                livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
                if livreur:
                    result['livreur'] = {
                        'id': livreur.id,
                        'name': livreur.name,
                        'user_id': livreur.user_id.id if livreur.user_id else None,
                    }
                else:
                    result['livreur'] = None
                    result['livreur_search'] = f"No livreur found for user_id={user.id}"
            else:
                result['current_user'] = None
            
            return self._json_response(result)
        except Exception as e:
            _logger.error(f"Debug auth error: {e}")
            return self._json_response({'error': str(e)}, 500)
    
    # ==================== USER INFO ENDPOINT ====================
    
    @http.route('/smart_delivery/api/user/info', type='http', auth='public', methods=['GET'], csrf=False)
    def get_user_info(self, **kwargs):
        """GET /smart_delivery/api/user/info - Get current user information and type"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            user = self._get_current_user()
            if not user:
                return self._json_response({
                    'error': 'User not found',
                    'code': 'USER_NOT_FOUND'
                }, 404)
            
            # Get user type
            user_type = self._get_user_type(user)
            
            # Get livreur info if user is a livreur
            livreur_info = None
            if user_type == 'livreur':
                livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
                if livreur:
                    livreur_info = {
                        'id': livreur.id,
                        'name': livreur.name,
                        'phone': livreur.phone,
                        'vehicle_type': livreur.vehicle_type,
                        'availability': livreur.availability,
                        'rating': livreur.rating,
                        'verified': livreur.verified,
                    }
            
            response_data = {
                'success': True,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'login': user.login,
                    'email': user.email,
                    'type': user_type,
                },
                'livreur': livreur_info,
            }
            
            self._log_api_call('/smart_delivery/api/user/info', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération info utilisateur: {e}")
            error_response = {'error': str(e), 'code': 'USER_INFO_ERROR'}
            self._log_api_call('/smart_delivery/api/user/info', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== DELIVERY ENDPOINTS ====================
    
    @http.route('/smart_delivery/api/delivery/create', type='http', auth='public', methods=['POST'], csrf=False)
    def create_delivery(self, **kwargs):
        """POST /smart_delivery/api/delivery/create - Crée une commande de livraison
        
        For Enterprise users: sender_id is automatically set to their company/partner
        For Admin users: sender_id must be provided
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            
            user_type = self._get_user_type(user)
            
            # For enterprise users, enforce sender_id to be their company
            if user_type == 'enterprise':
                # Enterprise users can only create orders for their company
                partner = user.partner_id
                company_partner_id = partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id
                
                # If sender_id is provided, validate it belongs to their company
                if data.get('sender_id'):
                    provided_sender_id = int(data['sender_id'])
                    # Check if provided sender belongs to user's company
                    sender = request.env['res.partner'].sudo().browse(provided_sender_id)
                    if sender.exists():
                        sender_company_id = sender.commercial_partner_id.id if sender.commercial_partner_id else sender.id
                        if sender_company_id != company_partner_id and sender.parent_id.id != company_partner_id:
                            return self._json_response({
                                'error': 'Vous ne pouvez créer des commandes que pour votre entreprise',
                                'code': 'SENDER_NOT_ALLOWED',
                                'allowed_company_id': company_partner_id,
                            }, 403)
                else:
                    # Default to company partner
                    data['sender_id'] = company_partner_id
            
            # Validation des données
            required_fields = ['sector_type', 'sender_id', 'receiver_name', 'receiver_phone',
                             'pickup_lat', 'pickup_long', 'drop_lat', 'drop_long']
            for field in required_fields:
                if field not in data:
                    return self._json_response({'error': f'Champ requis manquant: {field}'}, 400)
            
            # Préparer les valeurs de création
            order_vals = {
                'reference': data.get('reference'),
                'sector_type': data['sector_type'],
                'sender_id': data['sender_id'],
                'receiver_name': data['receiver_name'],
                'receiver_phone': data['receiver_phone'],
                'pickup_lat': float(data['pickup_lat']),
                'pickup_long': float(data['pickup_long']),
                'drop_lat': float(data['drop_lat']),
                'drop_long': float(data['drop_long']),
            }
            
            # Ajouter le livreur si spécifié
            if data.get('livreur_id'):
                livreur = request.env['delivery.livreur'].sudo().browse(int(data['livreur_id']))
                if livreur.exists():
                    order_vals['assigned_livreur_id'] = livreur.id
            
            # Créer la commande
            order = request.env['delivery.order'].sudo().create(order_vals)
            
            response_data = {
                'success': True,
                'order_id': order.id,
                'reference': order.name,
                'status': order.status,
                'sender_id': order.sender_id.id,
                'sender_name': order.sender_id.name,
            }
            
            self._log_api_call('/smart_delivery/api/delivery/create', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur création livraison: {e}")
            error_response = {'error': str(e)}
            self._log_api_call('/smart_delivery/api/delivery/create', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/delivery/status/<int:order_id>', type='http', auth='public', methods=['GET'], csrf=False)
    def get_delivery_status(self, order_id, **kwargs):
        """GET /smart_delivery/api/delivery/status/<id> - Retourne le statut complet
        
        Enterprise users can only see their own company's orders.
        Admin users can see all orders.
        Livreurs can see orders assigned to them.
        """
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            user = self._get_current_user()
            user_type = self._get_user_type(user)
            
            order = request.env['delivery.order'].sudo().browse(order_id)
            if not order.exists():
                return self._json_response({'error': 'Commande non trouvée'}, 404)
            
            # Access control based on user type
            if user_type == 'enterprise':
                # Enterprise users can only see their company's orders
                partner = user.partner_id
                company_partner_id = partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id
                sender_company_id = order.sender_id.commercial_partner_id.id if order.sender_id.commercial_partner_id else order.sender_id.id
                
                if sender_company_id != company_partner_id and order.sender_id.parent_id.id != company_partner_id:
                    return self._json_response({
                        'error': 'Accès refusé. Cette commande ne vous appartient pas.',
                        'code': 'ACCESS_DENIED'
                    }, 403)
            
            elif user_type == 'livreur':
                # Livreurs can only see orders assigned to them
                livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
                if not livreur or order.assigned_livreur_id.id != livreur.id:
                    return self._json_response({
                        'error': 'Accès refusé. Cette commande ne vous est pas assignée.',
                        'code': 'ORDER_NOT_ASSIGNED_TO_YOU'
                    }, 403)
            
            response_data = {
                'order_id': order.id,
                'reference': order.name,
                'status': order.status,
                'sector_type': order.sector_type,
                'sender': {
                    'id': order.sender_id.id,
                    'name': order.sender_id.name,
                },
                'receiver': {
                    'name': order.receiver_name,
                    'phone': order.receiver_phone,
                },
                'pickup': {
                    'lat': order.pickup_lat,
                    'long': order.pickup_long,
                },
                'drop': {
                    'lat': order.drop_lat,
                    'long': order.drop_long,
                },
                'livreur': {
                    'id': order.assigned_livreur_id.id,
                    'name': order.assigned_livreur_id.name,
                } if order.assigned_livreur_id else None,
                'distance_km': order.distance_km,
                'conditions': {
                    'otp_required': order.otp_required,
                    'signature_required': order.signature_required,
                    'photo_required': order.photo_required,
                    'biometric_required': order.biometric_required,
                },
            }
            
            # Ajouter les conditions validées
            if order.condition_ids:
                condition = order.condition_ids[0]
                response_data['validation'] = {
                    'otp_verified': condition.otp_verified,
                    'signature_provided': bool(condition.signature_file),
                    'photo_provided': bool(condition.photo_url),
                    'biometric_score': condition.biometric_score,
                    'validated': condition.validated,
                }
            
            self._log_api_call(f'/smart_delivery/api/delivery/status/{order_id}', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur statut livraison: {e}")
            error_response = {'error': str(e)}
            self._log_api_call(f'/smart_delivery/api/delivery/status/{order_id}', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/delivery/assign', type='http', auth='public', methods=['POST'], csrf=False)
    def assign_delivery(self, **kwargs):
        """POST /smart_delivery/api/delivery/assign - Déclenche le dispatching"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            order_id = data.get('order_id')
            
            if not order_id:
                return self._json_response({'error': 'order_id requis'}, 400)
            
            order = request.env['delivery.order'].sudo().browse(order_id)
            if not order.exists():
                return self._json_response({'error': 'Commande non trouvée'}, 404)
            
            # Si force=True, écrase le livreur déjà assigné
            force = data.get('force', False)
            order.assign_livreur(force=force)
            
            response_data = {
                'success': True,
                'order_id': order.id,
                'livreur_id': order.assigned_livreur_id.id if order.assigned_livreur_id else None,
                'livreur_name': order.assigned_livreur_id.name if order.assigned_livreur_id else None,
                'status': order.status,
            }
            
            self._log_api_call('/smart_delivery/api/delivery/assign', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur assignation livraison: {e}")
            error_response = {'error': str(e)}
            self._log_api_call('/smart_delivery/api/delivery/assign', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/my-orders', type='http', auth='public', methods=['GET'], csrf=False)
    def get_livreur_orders(self, **kwargs):
        """
        GET /smart_delivery/api/livreur/my-orders - Get all orders assigned to the authenticated livreur
        
        The livreur is automatically detected from the JWT token.
        
        Query Parameters:
            - status (optional): Filter by status (draft, assigned, on_way, delivered, failed)
            - limit (optional): Maximum number of orders to return (default: 50)
            - offset (optional): Number of orders to skip (default: 0)
        
        Response:
        {
            "success": true,
            "livreur": {
                "id": 1,
                "name": "John Doe",
                "phone": "+1234567890"
            },
            "orders_count": 10,
            "orders": [...]
        }
        """
        try:
            # Check auth and get livreur
            livreur, error = self._require_livreur()
            if error:
                return error
        except Exception as e:
            _logger.error(f"Auth error in my-orders: {e}")
            return self._json_response({'error': str(e), 'code': 'AUTH_ERROR'}, 500)
        
        try:
            # Get query parameters
            status_filter = kwargs.get('status')
            limit = int(kwargs.get('limit', 50))
            offset = int(kwargs.get('offset', 0))
            
            # Build domain - only orders assigned to THIS livreur
            domain = [('assigned_livreur_id', '=', livreur.id)]
            if status_filter:
                domain.append(('status', '=', status_filter))
            
            # Get orders
            orders = request.env['delivery.order'].sudo().search(
                domain,
                limit=limit,
                offset=offset,
                order='create_date desc'
            )
            total_count = request.env['delivery.order'].sudo().search_count(domain)
            
            # Build orders list with details
            orders_data = []
            for order in orders:
                order_data = {
                    'id': order.id,
                    'reference': order.name,
                    'external_reference': order.reference,
                    'status': order.status,
                    'sector_type': order.sector_type,
                    'sender': {
                        'id': order.sender_id.id,
                        'name': order.sender_id.name,
                        'phone': order.sender_id.phone or '',
                    },
                    'receiver': {
                        'name': order.receiver_name,
                        'phone': order.receiver_phone,
                    },
                    'pickup': {
                        'lat': order.pickup_lat,
                        'long': order.pickup_long,
                    },
                    'drop': {
                        'lat': order.drop_lat,
                        'long': order.drop_long,
                    },
                    'distance_km': order.distance_km,
                    'conditions': {
                        'otp_required': order.otp_required,
                        'signature_required': order.signature_required,
                        'photo_required': order.photo_required,
                        'biometric_required': order.biometric_required,
                    },
                    'created_at': order.create_date.isoformat() if order.create_date else None,
                }
                
                # Add validation status if conditions exist
                if order.condition_ids:
                    condition = order.condition_ids[0]
                    order_data['validation'] = {
                        'otp_verified': condition.otp_verified,
                        'otp_value': condition.otp_value if order.otp_required else None,
                        'signature_provided': bool(condition.signature_file),
                        'photo_provided': bool(condition.photo_url),
                        'biometric_score': condition.biometric_score,
                        'validated': condition.validated,
                    }
                else:
                    order_data['validation'] = None
                
                # Add billing info if exists
                if order.billing_id:
                    billing = order.billing_id[0]
                    order_data['billing'] = {
                        'base_tariff': billing.base_tariff,
                        'extra_fee': billing.extra_fee,
                        'total_amount': billing.total_amount,
                        'commission': billing.commission,
                    }
                else:
                    order_data['billing'] = None
                
                orders_data.append(order_data)
            
            response_data = {
                'success': True,
                'livreur': {
                    'id': livreur.id,
                    'name': livreur.name,
                    'phone': livreur.phone,
                    'vehicle_type': livreur.vehicle_type,
                    'availability': livreur.availability,
                    'rating': livreur.rating,
                },
                'pagination': {
                    'total': total_count,
                    'limit': limit,
                    'offset': offset,
                },
                'orders_count': len(orders_data),
                'orders': orders_data,
            }
            
            self._log_api_call('/smart_delivery/api/livreur/my-orders', kwargs, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération commandes livreur: {e}")
            error_response = {'error': str(e), 'code': 'LIVREUR_ORDERS_ERROR'}
            self._log_api_call('/smart_delivery/api/livreur/my-orders', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/orders/<int:order_id>/start', type='http', auth='public', methods=['POST'], csrf=False)
    def start_delivery(self, order_id, **kwargs):
        """
        POST /smart_delivery/api/livreur/orders/<order_id>/start
        
        Change order status from 'assigned' to 'on_way' (en route).
        The livreur is automatically detected from JWT token.
        Only orders assigned to the authenticated livreur can be started.
        
        Response:
        {
            "success": true,
            "order_id": 1,
            "reference": "DEL00001",
            "status": "on_way",
            "message": "Livraison démarrée avec succès"
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Validate order exists
            order = request.env['delivery.order'].sudo().browse(order_id)
            if not order.exists():
                return self._json_response({
                    'error': 'Commande non trouvée',
                    'code': 'ORDER_NOT_FOUND'
                }, 404)
            
            # Check if this order is assigned to THIS livreur
            if order.assigned_livreur_id.id != livreur.id:
                return self._json_response({
                    'error': 'Cette commande n\'est pas assignée à votre compte',
                    'code': 'ORDER_NOT_ASSIGNED_TO_YOU'
                }, 403)
            
            # Check current status
            if order.status != 'assigned':
                return self._json_response({
                    'error': f'Impossible de démarrer la livraison. Statut actuel: {order.status}. La commande doit être en statut "assigned".',
                    'code': 'INVALID_STATUS'
                }, 400)
            
            # Start the delivery (change status to on_way)
            order.action_start_delivery()
            
            response_data = {
                'success': True,
                'order_id': order.id,
                'reference': order.name,
                'previous_status': 'assigned',
                'status': order.status,
                'message': 'Livraison démarrée avec succès',
            }
            
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/start', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur démarrage livraison: {e}")
            error_response = {'error': str(e), 'code': 'START_DELIVERY_ERROR'}
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/start', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/orders/<int:order_id>/deliver', type='http', auth='public', methods=['POST'], csrf=False)
    def deliver_order(self, order_id, **kwargs):
        """
        POST /smart_delivery/api/livreur/orders/<order_id>/deliver
        
        Validate delivery conditions and mark order as delivered.
        The livreur is automatically detected from JWT token.
        Only orders assigned to the authenticated livreur can be delivered.
        
        Request Body (depending on order requirements):
        {
            "otp_value": "123456",           // Required if otp_required is true
            "signature": "base64_data...",   // Required if signature_required is true
            "signature_filename": "sig.png", // Optional, defaults to "signature.png"
            "photo_url": "https://...",      // Required if photo_required is true
            "biometric_score": 0.85          // Required if biometric_required is true (min 0.7)
        }
        
        Response:
        {
            "success": true,
            "order_id": 1,
            "reference": "DEL00001",
            "status": "delivered",
            "message": "Livraison validée avec succès",
            "billing": { ... }
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            
            # Validate order exists
            order = request.env['delivery.order'].sudo().browse(order_id)
            if not order.exists():
                return self._json_response({
                    'error': 'Commande non trouvée',
                    'code': 'ORDER_NOT_FOUND'
                }, 404)
            
            # Check if this order is assigned to THIS livreur
            if order.assigned_livreur_id.id != livreur.id:
                return self._json_response({
                    'error': 'Cette commande n\'est pas assignée à votre compte',
                    'code': 'ORDER_NOT_ASSIGNED_TO_YOU'
                }, 403)
            
            # Check current status - must be on_way
            if order.status != 'on_way':
                return self._json_response({
                    'error': f'Impossible de valider la livraison. Statut actuel: {order.status}. La commande doit être en statut "on_way" (en route).',
                    'code': 'INVALID_STATUS'
                }, 400)
            
            # Get or create condition record
            condition = order.condition_ids[:1]
            if not condition:
                condition = request.env['delivery.condition'].sudo().create({
                    'order_id': order.id,
                })
            
            # Collect validation errors
            validation_errors = []
            
            # Build requirements info for response
            requirements = {
                'otp_required': order.otp_required,
                'signature_required': order.signature_required,
                'photo_required': order.photo_required,
                'biometric_required': order.biometric_required,
            }
            
            # Validate OTP if required
            if order.otp_required:
                otp_value = data.get('otp_value')
                if not otp_value:
                    validation_errors.append('OTP requis mais non fourni')
                elif condition.otp_value and condition.otp_value != otp_value:
                    validation_errors.append('OTP invalide')
                else:
                    condition.sudo().write({'otp_verified': True})
            
            # Validate signature if required
            if order.signature_required:
                signature = data.get('signature')
                if not signature:
                    validation_errors.append('Signature requise mais non fournie')
                else:
                    condition.sudo().write({
                        'signature_file': signature,
                        'signature_filename': data.get('signature_filename', 'signature.png'),
                    })
            
            # Validate photo if required
            if order.photo_required:
                photo_url = data.get('photo_url')
                if not photo_url:
                    validation_errors.append('Photo requise mais non fournie')
                else:
                    condition.sudo().write({'photo_url': photo_url})
            
            # Validate biometric if required
            if order.biometric_required:
                biometric_score = data.get('biometric_score')
                if biometric_score is None:
                    validation_errors.append('Score biométrique requis mais non fourni')
                else:
                    score = float(biometric_score)
                    if score < 0.7:
                        validation_errors.append(f'Score biométrique insuffisant: {score}. Minimum requis: 0.7')
                    else:
                        condition.sudo().write({'biometric_score': score})
            
            # If there are validation errors, return them
            if validation_errors:
                return self._json_response({
                    'success': False,
                    'error': 'Validation échouée',
                    'code': 'VALIDATION_FAILED',
                    'validation_errors': validation_errors,
                    'requirements': requirements,
                }, 400)
            
            # All validations passed - mark as validated and delivered
            condition.sudo().write({'validated': True})
            order.sudo().write({'status': 'delivered'})
            
            # Generate billing
            billing_data = None
            try:
                billing = order._generate_billing()
                if billing:
                    billing_data = {
                        'id': billing.id,
                        'base_tariff': billing.base_tariff,
                        'extra_fee': billing.extra_fee,
                        'total_amount': billing.total_amount,
                        'commission': billing.commission,
                        'distance_km': billing.distance_km,
                    }
            except Exception as billing_error:
                _logger.warning(f"Erreur génération facturation: {billing_error}")
            
            response_data = {
                'success': True,
                'order_id': order.id,
                'reference': order.name,
                'previous_status': 'on_way',
                'status': order.status,
                'message': 'Livraison validée avec succès',
                'validation': {
                    'otp_verified': condition.otp_verified if order.otp_required else None,
                    'signature_provided': bool(condition.signature_file) if order.signature_required else None,
                    'photo_provided': bool(condition.photo_url) if order.photo_required else None,
                    'biometric_score': condition.biometric_score if order.biometric_required else None,
                    'validated': condition.validated,
                },
                'billing': billing_data,
            }
            
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/deliver', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur validation livraison: {e}")
            error_response = {'error': str(e), 'code': 'DELIVER_ERROR'}
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/deliver', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/location', type='http', auth='public', methods=['POST'], csrf=False)
    def update_livreur_location(self, **kwargs):
        """
        POST /smart_delivery/api/livreur/location - Update GPS location for the authenticated livreur
        
        The livreur is automatically detected from JWT token.
        
        Request Body:
        {
            "lat": 33.5731,
            "long": -7.5898
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            lat = data.get('lat')
            long = data.get('long')
            
            if lat is None or long is None:
                return self._json_response({
                    'error': 'lat et long requis',
                    'code': 'MISSING_COORDINATES'
                }, 400)
            
            livreur.sudo().write({
                'current_lat': float(lat),
                'current_long': float(long),
            })
            
            response_data = {
                'success': True,
                'livreur_id': livreur.id,
                'lat': livreur.current_lat,
                'long': livreur.current_long,
            }
            
            self._log_api_call('/smart_delivery/api/livreur/location', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur mise à jour position livreur: {e}")
            error_response = {'error': str(e), 'code': 'LOCATION_UPDATE_ERROR'}
            self._log_api_call('/smart_delivery/api/livreur/location', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/stats', type='http', auth='public', methods=['GET'], csrf=False)
    def get_livreur_stats(self, **kwargs):
        """
        GET /smart_delivery/api/livreur/stats - Get delivery statistics for the authenticated livreur
        
        The livreur is automatically detected from JWT token.
        
        Response:
        {
            "success": true,
            "livreur": {
                "id": 1,
                "name": "John Doe"
            },
            "stats": {
                "today": 5,
                "in_progress": 2,
                "delivered": 10,
                "failed": 1
            }
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            DeliveryOrder = request.env['delivery.order'].sudo()
            
            # Base domain: orders assigned to this livreur
            base_domain = [('assigned_livreur_id', '=', livreur.id)]
            
            # Today's date range (start and end of today)
            today_start = fields.Datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            # Count today's deliveries (created or assigned today)
            today_domain = base_domain + [
                ('create_date', '>=', today_start),
                ('create_date', '<', today_end)
            ]
            today_count = DeliveryOrder.search_count(today_domain)
            
            # Count in progress (assigned + on_way)
            in_progress_domain = base_domain + [('status', 'in', ['assigned', 'on_way'])]
            in_progress_count = DeliveryOrder.search_count(in_progress_domain)
            
            # Count delivered (all time)
            delivered_domain = base_domain + [('status', '=', 'delivered')]
            delivered_count = DeliveryOrder.search_count(delivered_domain)
            
            # Count failed (all time)
            failed_domain = base_domain + [('status', '=', 'failed')]
            failed_count = DeliveryOrder.search_count(failed_domain)
            
            response_data = {
                'success': True,
                'livreur': {
                    'id': livreur.id,
                    'name': livreur.name,
                },
                'stats': {
                    'today': today_count,
                    'in_progress': in_progress_count,
                    'delivered': delivered_count,
                    'failed': failed_count,
                }
            }
            
            self._log_api_call('/smart_delivery/api/livreur/stats', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération statistiques livreur: {e}")
            error_response = {'error': str(e), 'code': 'STATS_ERROR'}
            self._log_api_call('/smart_delivery/api/livreur/stats', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== LIVREUR PROFILE MANAGEMENT ====================
    
    @http.route('/smart_delivery/api/livreur/change-password', type='http', auth='public', methods=['POST'], csrf=False)
    def livreur_change_password(self, **kwargs):
        """
        POST /smart_delivery/api/livreur/change-password - Change livreur password
        
        The livreur is automatically detected from JWT token.
        
        Request Body:
        {
            "current_password": "oldpassword",
            "new_password": "newpassword123"
        }
        
        Response:
        {
            "success": true,
            "message": "Mot de passe modifié avec succès"
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            
            if not current_password or not new_password:
                return self._json_response({
                    'success': False,
                    'error': 'current_password et new_password sont requis',
                    'code': 'MISSING_FIELDS'
                }, 400)
            
            if len(new_password) < 6:
                return self._json_response({
                    'success': False,
                    'error': 'Le nouveau mot de passe doit contenir au moins 6 caractères',
                    'code': 'PASSWORD_TOO_SHORT'
                }, 400)
            
            # Verify current password
            user = livreur.user_id
            if not user:
                return self._json_response({
                    'success': False,
                    'error': 'Compte utilisateur non trouvé',
                    'code': 'USER_NOT_FOUND'
                }, 400)
            
            # Try to authenticate with current password
            try:
                from ..utils.jwt_auth import JWTAuth
                auth_user = JWTAuth.authenticate_user(request.env, user.login, current_password)
                if not auth_user:
                    return self._json_response({
                        'success': False,
                        'error': 'Mot de passe actuel incorrect',
                        'code': 'INVALID_CURRENT_PASSWORD'
                    }, 401)
            except Exception as e:
                _logger.error(f"Password verification error: {e}")
                return self._json_response({
                    'success': False,
                    'error': 'Mot de passe actuel incorrect',
                    'code': 'INVALID_CURRENT_PASSWORD'
                }, 401)
            
            # Update password
            user.sudo().write({'password': new_password})
            
            response_data = {
                'success': True,
                'message': 'Mot de passe modifié avec succès'
            }
            
            self._log_api_call('/smart_delivery/api/livreur/change-password', 
                             {'livreur_id': livreur.id}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Error changing livreur password: {e}")
            error_response = {'success': False, 'error': str(e), 'code': 'PASSWORD_CHANGE_ERROR'}
            self._log_api_call('/smart_delivery/api/livreur/change-password', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/update-profile', type='http', auth='public', methods=['POST'], csrf=False)
    def livreur_update_profile(self, **kwargs):
        """
        POST /smart_delivery/api/livreur/update-profile - Update livreur profile (name and/or photo)
        
        The livreur is automatically detected from JWT token.
        
        Request Body (JSON or multipart/form-data):
        {
            "name": "Nouveau Nom",           # Optional
            "livreur_photo": "<base64>"      # Optional: Photo d'identité du livreur
        }
        
        Response:
        {
            "success": true,
            "message": "Profil mis à jour avec succès",
            "livreur": {
                "id": 1,
                "name": "Nouveau Nom",
                "has_photo": true
            }
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Get data from request - support both JSON and multipart form data
            if request.httprequest.content_type and 'application/json' in request.httprequest.content_type:
                data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            else:
                # Multipart form data
                data = dict(request.httprequest.form)
            
            # Check if at least one field is provided
            name = data.get('name', '').strip() if data.get('name') else None
            photo_data = None
            photo_filename = None
            
            # Check for file upload in multipart form
            if 'livreur_photo' in request.httprequest.files:
                file = request.httprequest.files['livreur_photo']
                if file and file.filename:
                    import base64
                    photo_data = base64.b64encode(file.read()).decode('utf-8')
                    photo_filename = file.filename
            
            # Check for base64 data in JSON/form data
            elif data.get('livreur_photo'):
                photo_data = data.get('livreur_photo')
                # If it already contains data: prefix, extract base64 part
                if isinstance(photo_data, str) and 'base64,' in photo_data:
                    photo_data = photo_data.split('base64,')[1]
                photo_filename = data.get('livreur_photo_filename', 'photo.jpg')
            
            if not name and not photo_data:
                return self._json_response({
                    'success': False,
                    'error': 'Au moins un champ (name ou livreur_photo) doit être fourni',
                    'code': 'NO_FIELDS_PROVIDED'
                }, 400)
            
            # Prepare update values
            update_vals = {}
            if name:
                update_vals['name'] = name
            if photo_data:
                update_vals['livreur_photo'] = photo_data
                if photo_filename:
                    update_vals['livreur_photo_filename'] = photo_filename
            
            # Update livreur
            livreur.sudo().write(update_vals)
            
            response_data = {
                'success': True,
                'message': 'Profil mis à jour avec succès',
                'livreur': {
                    'id': livreur.id,
                    'name': livreur.name,
                    'has_photo': bool(livreur.livreur_photo),
                }
            }
            
            self._log_api_call('/smart_delivery/api/livreur/update-profile', 
                             {'livreur_id': livreur.id, 'updated_fields': list(update_vals.keys())}, 
                             response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Error updating livreur profile: {e}")
            error_response = {'success': False, 'error': str(e), 'code': 'PROFILE_UPDATE_ERROR'}
            self._log_api_call('/smart_delivery/api/livreur/update-profile', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== ORDER OTP ENDPOINT (SECURED) ====================
    
    @http.route('/smart_delivery/api/livreur/orders/<int:order_id>/otp', type='http', auth='public', methods=['GET'], csrf=False)
    def get_order_otp(self, order_id, **kwargs):
        """
        GET /smart_delivery/api/livreur/orders/{order_id}/otp - Get OTP for an assigned order
        
        Only the assigned livreur can see the OTP for their orders.
        The livreur is automatically detected from JWT token.
        
        Response:
        {
            "success": true,
            "order": {
                "id": 5,
                "name": "DEL00005",
                "state": "assigned"
            },
            "otp": {
                "value": "123456",
                "required": true,
                "verified": false
            }
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Find the order
            order = request.env['delivery.order'].sudo().browse(order_id)
            
            if not order.exists():
                return self._json_response({
                    'success': False,
                    'error': 'Commande non trouvée',
                    'code': 'ORDER_NOT_FOUND'
                }, 404)
            
            # Check if this order is assigned to THIS livreur
            if not order.assigned_livreur_id or order.assigned_livreur_id.id != livreur.id:
                return self._json_response({
                    'success': False,
                    'error': 'Cette commande n\'est pas assignée à votre compte',
                    'code': 'ORDER_NOT_ASSIGNED_TO_YOU'
                }, 403)
            
            # Get the condition record for this order
            condition = request.env['delivery.condition'].sudo().search([
                ('order_id', '=', order.id)
            ], limit=1)
            
            otp_data = {
                'value': None,
                'required': order.otp_required,
                'verified': False
            }
            
            if condition:
                otp_data['value'] = condition.otp_value
                otp_data['verified'] = condition.otp_verified
            
            response_data = {
                'success': True,
                'order': {
                    'id': order.id,
                    'name': order.name,
                    'status': order.status,
                    'receiver_name': order.receiver_name,
                    'receiver_phone': order.receiver_phone,
                    'delivery_address': order.delivery_address if hasattr(order, 'delivery_address') else None,
                },
                'otp': otp_data,
            }
            
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/otp', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Error getting OTP for order {order_id}: {e}")
            error_response = {'success': False, 'error': str(e), 'code': 'OTP_ERROR'}
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/otp', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/orders/<int:order_id>/details', type='http', auth='public', methods=['GET'], csrf=False)
    def get_order_details(self, order_id, **kwargs):
        """
        GET /smart_delivery/api/livreur/orders/{order_id}/details - Get full order details
        
        Only the assigned livreur can see details of their orders.
        The livreur is automatically detected from JWT token.
        
        Response:
        {
            "success": true,
            "order": { ... },
            "requirements": { ... },
            "condition": { ... }
        }
        """
        # Check auth and get livreur
        livreur, error = self._require_livreur()
        if error:
            return error
        
        try:
            # Find the order
            order = request.env['delivery.order'].sudo().browse(order_id)
            
            if not order.exists():
                return self._json_response({
                    'success': False,
                    'error': 'Commande non trouvée',
                    'code': 'ORDER_NOT_FOUND'
                }, 404)
            
            # Check if this order is assigned to THIS livreur
            if not order.assigned_livreur_id or order.assigned_livreur_id.id != livreur.id:
                return self._json_response({
                    'success': False,
                    'error': 'Cette commande n\'est pas assignée à votre compte',
                    'code': 'ORDER_NOT_ASSIGNED_TO_YOU'
                }, 403)
            
            # Get the condition record
            condition = request.env['delivery.condition'].sudo().search([
                ('order_id', '=', order.id)
            ], limit=1)
            
            response_data = {
                'success': True,
                'order': {
                    'id': order.id,
                    'name': order.name,
                    'status': order.status,
                    'sector_type': order.sector_type,
                    'sender': {
                        'id': order.sender_id.id if order.sender_id else None,
                        'name': order.sender_id.name if order.sender_id else None,
                    },
                    'receiver': {
                        'name': order.receiver_name,
                        'phone': order.receiver_phone,
                    },
                    'pickup': {
                        'lat': order.pickup_lat,
                        'long': order.pickup_long,
                    },
                    'delivery': {
                        'lat': order.drop_lat,
                        'long': order.drop_long,
                    },
                    'distance_km': order.distance_km,
                },
                'requirements': {
                    'otp_required': order.otp_required,
                    'signature_required': order.signature_required if hasattr(order, 'signature_required') else False,
                    'photo_required': order.photo_required if hasattr(order, 'photo_required') else False,
                    'biometric_required': order.biometric_required if hasattr(order, 'biometric_required') else False,
                },
                'condition': {
                    'otp_value': condition.otp_value if condition else None,
                    'otp_verified': condition.otp_verified if condition else False,
                    'signature_uploaded': bool(condition.signature_file) if condition else False,
                    'photo_url': condition.photo_url if condition else None,
                    'biometric_score': condition.biometric_score if condition else None,
                    'validated': condition.validated if condition else False,
                } if condition else None,
            }
            
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/details', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Error getting details for order {order_id}: {e}")
            error_response = {'success': False, 'error': str(e), 'code': 'DETAILS_ERROR'}
            self._log_api_call(f'/smart_delivery/api/livreur/orders/{order_id}/details', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== ENTERPRISE ENDPOINTS ====================
    
    @http.route('/smart_delivery/api/enterprise/my-orders', type='http', auth='public', methods=['GET'], csrf=False)
    def get_enterprise_orders(self, **kwargs):
        """
        GET /smart_delivery/api/enterprise/my-orders - Get all orders for the enterprise
        
        The enterprise is automatically detected from the JWT token.
        
        Query Parameters:
            - status (optional): Filter by status (draft, assigned, on_way, delivered, failed)
            - limit (optional): Maximum number of orders to return (default: 50)
            - offset (optional): Number of orders to skip (default: 0)
        
        Response:
        {
            "success": true,
            "enterprise": {
                "id": 1,
                "name": "Company Name"
            },
            "orders_count": 10,
            "orders": [...]
        }
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            user_type = self._get_user_type(user)
            
            # Get query parameters
            status_filter = kwargs.get('status')
            limit = int(kwargs.get('limit', 50))
            offset = int(kwargs.get('offset', 0))
            
            # Build domain based on user type
            domain = []
            
            if user_type == 'enterprise':
                # Enterprise users can only see their company's orders
                partner = user.partner_id
                company_partner_id = partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id
                domain = [
                    '|',
                    ('sender_id', '=', company_partner_id),
                    ('sender_id.parent_id', '=', company_partner_id)
                ]
            # Admin can see all orders (no additional domain)
            
            if status_filter:
                domain.append(('status', '=', status_filter))
            
            # Get orders
            orders = request.env['delivery.order'].sudo().search(
                domain,
                limit=limit,
                offset=offset,
                order='create_date desc'
            )
            total_count = request.env['delivery.order'].sudo().search_count(domain)
            
            # Build orders list with details
            orders_data = []
            for order in orders:
                order_data = {
                    'id': order.id,
                    'reference': order.name,
                    'external_reference': order.reference,
                    'status': order.status,
                    'sector_type': order.sector_type,
                    'sender': {
                        'id': order.sender_id.id,
                        'name': order.sender_id.name,
                    },
                    'receiver': {
                        'name': order.receiver_name,
                        'phone': order.receiver_phone,
                    },
                    'pickup': {
                        'lat': order.pickup_lat,
                        'long': order.pickup_long,
                    },
                    'drop': {
                        'lat': order.drop_lat,
                        'long': order.drop_long,
                    },
                    'distance_km': order.distance_km,
                    'livreur': {
                        'id': order.assigned_livreur_id.id,
                        'name': order.assigned_livreur_id.name,
                    } if order.assigned_livreur_id else None,
                    'created_at': order.create_date.isoformat() if order.create_date else None,
                }
                
                # Add billing info if exists
                if order.billing_id:
                    billing = order.billing_id[0]
                    order_data['billing'] = {
                        'base_tariff': billing.base_tariff,
                        'extra_fee': billing.extra_fee,
                        'total_amount': billing.total_amount,
                        'state': billing.state,
                    }
                else:
                    order_data['billing'] = None
                
                orders_data.append(order_data)
            
            # Enterprise info
            enterprise_info = None
            if user_type == 'enterprise':
                partner = user.partner_id
                enterprise_info = {
                    'id': partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id,
                    'name': partner.commercial_partner_id.name if partner.commercial_partner_id else partner.name,
                }
            
            response_data = {
                'success': True,
                'user_type': user_type,
                'enterprise': enterprise_info,
                'pagination': {
                    'total': total_count,
                    'limit': limit,
                    'offset': offset,
                },
                'orders_count': len(orders_data),
                'orders': orders_data,
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/my-orders', kwargs, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération commandes entreprise: {e}")
            error_response = {'error': str(e), 'code': 'ENTERPRISE_ORDERS_ERROR'}
            self._log_api_call('/smart_delivery/api/enterprise/my-orders', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/enterprise/my-billings', type='http', auth='public', methods=['GET'], csrf=False)
    def get_enterprise_billings(self, **kwargs):
        """
        GET /smart_delivery/api/enterprise/my-billings - Get all billings for the enterprise
        
        The enterprise is automatically detected from the JWT token.
        
        Query Parameters:
            - state (optional): Filter by state (draft, confirmed, paid, cancelled)
            - limit (optional): Maximum number of billings to return (default: 50)
            - offset (optional): Number of billings to skip (default: 0)
        
        Response:
        {
            "success": true,
            "enterprise": {...},
            "billings_count": 10,
            "billings": [...]
        }
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            user_type = self._get_user_type(user)
            
            # Get query parameters
            state_filter = kwargs.get('state')
            limit = int(kwargs.get('limit', 50))
            offset = int(kwargs.get('offset', 0))
            
            # Build domain based on user type
            domain = []
            
            if user_type == 'enterprise':
                # Enterprise users can only see their company's billings
                partner = user.partner_id
                company_partner_id = partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id
                domain = [
                    '|',
                    ('order_id.sender_id', '=', company_partner_id),
                    ('order_id.sender_id.parent_id', '=', company_partner_id)
                ]
            # Admin can see all billings (no additional domain)
            
            if state_filter:
                domain.append(('state', '=', state_filter))
            
            # Get billings
            billings = request.env['delivery.billing'].sudo().search(
                domain,
                limit=limit,
                offset=offset,
                order='id desc'
            )
            total_count = request.env['delivery.billing'].sudo().search_count(domain)
            
            # Build billings list with details
            billings_data = []
            for billing in billings:
                billing_data = {
                    'id': billing.id,
                    'order': {
                        'id': billing.order_id.id,
                        'reference': billing.order_id.name,
                        'status': billing.order_id.status,
                    },
                    'distance_km': billing.distance_km,
                    'base_tariff': billing.base_tariff,
                    'extra_fee': billing.extra_fee,
                    'total_amount': billing.total_amount,
                    'commission': billing.commission,
                    'state': billing.state,
                    'notes': billing.notes,
                }
                billings_data.append(billing_data)
            
            # Enterprise info
            enterprise_info = None
            if user_type == 'enterprise':
                partner = user.partner_id
                enterprise_info = {
                    'id': partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id,
                    'name': partner.commercial_partner_id.name if partner.commercial_partner_id else partner.name,
                }
            
            response_data = {
                'success': True,
                'user_type': user_type,
                'enterprise': enterprise_info,
                'pagination': {
                    'total': total_count,
                    'limit': limit,
                    'offset': offset,
                },
                'billings_count': len(billings_data),
                'billings': billings_data,
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/my-billings', kwargs, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération factures entreprise: {e}")
            error_response = {'error': str(e), 'code': 'ENTERPRISE_BILLINGS_ERROR'}
            self._log_api_call('/smart_delivery/api/enterprise/my-billings', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/enterprise/stats', type='http', auth='public', methods=['GET'], csrf=False)
    def get_enterprise_stats(self, **kwargs):
        """
        GET /smart_delivery/api/enterprise/stats - Get delivery statistics for the enterprise
        
        The enterprise is automatically detected from JWT token.
        
        Response:
        {
            "success": true,
            "enterprise": {...},
            "stats": {
                "total_orders": 100,
                "delivered": 80,
                "in_progress": 15,
                "failed": 5,
                "total_spent": 5000.00
            }
        }
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            user_type = self._get_user_type(user)
            DeliveryOrder = request.env['delivery.order'].sudo()
            DeliveryBilling = request.env['delivery.billing'].sudo()
            
            # Build domain based on user type
            base_domain = []
            
            if user_type == 'enterprise':
                partner = user.partner_id
                company_partner_id = partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id
                base_domain = [
                    '|',
                    ('sender_id', '=', company_partner_id),
                    ('sender_id.parent_id', '=', company_partner_id)
                ]
            
            # Count statistics
            total_orders = DeliveryOrder.search_count(base_domain)
            delivered_count = DeliveryOrder.search_count(base_domain + [('status', '=', 'delivered')])
            in_progress_count = DeliveryOrder.search_count(base_domain + [('status', 'in', ['assigned', 'on_way'])])
            failed_count = DeliveryOrder.search_count(base_domain + [('status', '=', 'failed')])
            draft_count = DeliveryOrder.search_count(base_domain + [('status', '=', 'draft')])
            
            # Calculate total spent
            billing_domain = []
            if user_type == 'enterprise':
                billing_domain = [
                    '|',
                    ('order_id.sender_id', '=', company_partner_id),
                    ('order_id.sender_id.parent_id', '=', company_partner_id)
                ]
            
            billings = DeliveryBilling.search(billing_domain)
            total_spent = sum(b.total_amount for b in billings)
            total_paid = sum(b.total_amount for b in billings if b.state == 'paid')
            
            # Enterprise info
            enterprise_info = None
            if user_type == 'enterprise':
                partner = user.partner_id
                enterprise_info = {
                    'id': partner.commercial_partner_id.id if partner.commercial_partner_id else partner.id,
                    'name': partner.commercial_partner_id.name if partner.commercial_partner_id else partner.name,
                }
            
            response_data = {
                'success': True,
                'user_type': user_type,
                'enterprise': enterprise_info,
                'stats': {
                    'total_orders': total_orders,
                    'draft': draft_count,
                    'in_progress': in_progress_count,
                    'delivered': delivered_count,
                    'failed': failed_count,
                    'total_spent': total_spent,
                    'total_paid': total_paid,
                }
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/stats', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération statistiques entreprise: {e}")
            error_response = {'error': str(e), 'code': 'ENTERPRISE_STATS_ERROR'}
            self._log_api_call('/smart_delivery/api/enterprise/stats', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/enterprise/livreurs-by-sector', type='http', auth='public', methods=['GET'], csrf=False)
    def get_livreurs_by_sector(self, **kwargs):
        """
        GET /smart_delivery/api/enterprise/livreurs-by-sector - Get livreurs by sector type
        
        Only accessible by enterprise or admin users.
        
        Query Parameters:
            - sector (required): Sector type code (standard, premium, express, fragile, medical)
            - available_only (optional): If true, only return available livreurs (default: true)
            - verified_only (optional): If true, only return verified livreurs (default: false)
            - limit (optional): Maximum number of livreurs to return (default: 50)
            - offset (optional): Number of livreurs to skip (default: 0)
        
        Response:
        {
            "success": true,
            "sector": {
                "sector_type": "express",
                "description": "..."
            },
            "livreurs_count": 5,
            "livreurs": [...]
        }
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            # Get query parameters
            sector_code = kwargs.get('sector')
            if not sector_code:
                return self._json_response({
                    'error': 'Le paramètre "sector" est requis',
                    'code': 'MISSING_SECTOR',
                    'valid_sectors': ['standard', 'premium', 'express', 'fragile', 'medical']
                }, 400)
            
            # Validate sector code
            valid_sectors = ['standard', 'premium', 'express', 'fragile', 'medical']
            if sector_code not in valid_sectors:
                return self._json_response({
                    'error': f'Secteur invalide: {sector_code}',
                    'code': 'INVALID_SECTOR',
                    'valid_sectors': valid_sectors
                }, 400)
            
            available_only = kwargs.get('available_only', 'true').lower() == 'true'
            verified_only = kwargs.get('verified_only', 'false').lower() == 'true'
            limit = int(kwargs.get('limit', 50))
            offset = int(kwargs.get('offset', 0))
            
            # Find the sector rule
            sector_rule = request.env['sector.rule'].sudo().search([('sector_type', '=', sector_code)], limit=1)
            if not sector_rule:
                return self._json_response({
                    'error': f'Règle de secteur non trouvée: {sector_code}',
                    'code': 'SECTOR_NOT_FOUND'
                }, 404)
            
            # Build domain for livreurs
            domain = [('sector_ids', 'in', [sector_rule.id])]
            
            if available_only:
                domain.append(('availability', '=', True))
            
            if verified_only:
                domain.append(('verified', '=', True))
            
            # Search livreurs
            livreurs = request.env['delivery.livreur'].sudo().search(
                domain,
                limit=limit,
                offset=offset,
                order='rating desc, name asc'
            )
            total_count = request.env['delivery.livreur'].sudo().search_count(domain)
            
            # Build livreurs list
            livreurs_data = []
            for livreur in livreurs:
                livreur_data = {
                    'id': livreur.id,
                    'name': livreur.name,
                    'phone': livreur.phone,
                    'vehicle_type': livreur.vehicle_type,
                    'availability': livreur.availability,
                    'verified': livreur.verified,
                    'rating': livreur.rating,
                    'sectors': [s.sector_type for s in livreur.sector_ids],
                    'current_location': {
                        'lat': livreur.current_lat,
                        'long': livreur.current_long,
                    } if livreur.current_lat and livreur.current_long else None,
                }
                livreurs_data.append(livreur_data)
            
            response_data = {
                'success': True,
                'sector': {
                    'id': sector_rule.id,
                    'sector_type': sector_rule.sector_type,
                    'description': sector_rule.description or '',
                    'requirements': {
                        'otp_required': sector_rule.otp_required,
                        'signature_required': sector_rule.signature_required,
                        'photo_required': sector_rule.photo_required,
                        'biometric_required': sector_rule.biometric_required,
                    },
                },
                'filters': {
                    'available_only': available_only,
                    'verified_only': verified_only,
                },
                'pagination': {
                    'total': total_count,
                    'limit': limit,
                    'offset': offset,
                },
                'livreurs_count': len(livreurs_data),
                'livreurs': livreurs_data,
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/livreurs-by-sector', kwargs, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération livreurs par secteur: {e}")
            error_response = {'error': str(e), 'code': 'LIVREURS_BY_SECTOR_ERROR'}
            self._log_api_call('/smart_delivery/api/enterprise/livreurs-by-sector', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/enterprise/sectors', type='http', auth='public', methods=['GET'], csrf=False)
    def get_sectors(self, **kwargs):
        """
        GET /smart_delivery/api/enterprise/sectors - Get all available sector rules
        
        Only accessible by enterprise or admin users.
        
        Response:
        {
            "success": true,
            "sectors": [
                {
                    "id": 1,
                    "sector_type": "standard",
                    "description": "Livraison standard...",
                    "requirements": {...},
                    "livreur_count": 10
                }
            ]
        }
        """
        # Require enterprise or admin user
        user, auth_error = self._require_enterprise_or_admin()
        if auth_error:
            return auth_error
        
        try:
            # Get all sector rules
            sectors = request.env['sector.rule'].sudo().search([], order='sector_type asc')
            
            sectors_data = []
            for sector in sectors:
                sectors_data.append({
                    'id': sector.id,
                    'sector_type': sector.sector_type,
                    'description': sector.description or '',
                    'requirements': {
                        'otp_required': sector.otp_required,
                        'signature_required': sector.signature_required,
                        'photo_required': sector.photo_required,
                        'biometric_required': sector.biometric_required,
                    },
                    'livreur_count': sector.livreur_count,
                })
            
            response_data = {
                'success': True,
                'sectors_count': len(sectors_data),
                'sectors': sectors_data,
            }
            
            self._log_api_call('/smart_delivery/api/enterprise/sectors', {}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur récupération secteurs: {e}")
            error_response = {'error': str(e), 'code': 'SECTORS_ERROR'}
            self._log_api_call('/smart_delivery/api/enterprise/sectors', {}, error_response, 500, e)
            return self._json_response(error_response, 500)
