# -*- coding: utf-8 -*-

import json
import logging
from odoo import http
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
                    # Set the user in the environment
                    user = request.env['res.users'].sudo().browse(payload.get('user_id'))
                    if user.exists():
                        request.session.uid = user.id
                        request.uid = user.id
                        request.env = request.env(user=user.id)
                        return True
        except Exception as e:
            _logger.error(f"JWT authentication error: {e}")
        return False
    
    def _authenticate(self):
        """Authenticate request via session or JWT"""
        # Check session authentication
        if request.session.uid:
            return True
        
        # Check JWT authentication
        if self._authenticate_jwt():
            return True
        
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
    
    # ==================== AUTHENTICATION ENDPOINT ====================
    
    @http.route('/smart_delivery/api/auth/login', type='http', auth='none', methods=['POST'], csrf=False)
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
            
            response_data = {
                'success': True,
                'token': token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'login': user.login,
                },
                'expires_in': JWTAuth.TOKEN_EXPIRY_HOURS * 3600,  # seconds
            }
            
            self._log_api_call('/smart_delivery/api/auth/login', {'login': login}, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur login: {e}")
            error_response = {'error': str(e), 'code': 'LOGIN_ERROR'}
            self._log_api_call('/smart_delivery/api/auth/login', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    # ==================== SWAGGER DOCUMENTATION ====================
    
    @http.route('/smart_delivery/api/docs', type='http', auth='none', methods=['GET'], csrf=False)
    def swagger_docs(self, **kwargs):
        """GET /smart_delivery/api/docs - Swagger/OpenAPI documentation"""
        swagger_spec = self._get_swagger_spec()
        return request.make_response(
            json.dumps(swagger_spec, indent=2),
            headers=[('Content-Type', 'application/json')]
        )
    
    @http.route('/smart_delivery/api/docs/ui', type='http', auth='none', methods=['GET'], csrf=False)
    def swagger_ui(self, **kwargs):
        """GET /smart_delivery/api/docs/ui - Swagger UI HTML page"""
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
    
    def _get_swagger_spec(self):
        """Generate OpenAPI 3.0 specification"""
        base_url = request.httprequest.host_url.rstrip('/')
        
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Smart Delivery API",
                "description": "API for managing delivery orders, tracking status, assigning drivers, and validating delivery conditions",
                "version": "1.0.0",
                "contact": {
                    "name": "Smart Delivery Team",
                    "url": "https://www.odoo.com"
                }
            },
            "servers": [
                {
                    "url": base_url,
                    "description": "Odoo Server"
                }
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                        "description": "JWT token obtained from /smart_delivery/api/auth/login"
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
                    "LoginRequest": {
                        "type": "object",
                        "required": ["login", "password"],
                        "properties": {
                            "login": {"type": "string", "example": "user@example.com"},
                            "password": {"type": "string", "format": "password"}
                        }
                    },
                    "LoginResponse": {
                        "type": "object",
                        "properties": {
                            "success": {"type": "boolean"},
                            "token": {"type": "string"},
                            "user": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "integer"},
                                    "name": {"type": "string"},
                                    "login": {"type": "string"}
                                }
                            },
                            "expires_in": {"type": "integer"}
                        }
                    },
                    "DeliveryOrder": {
                        "type": "object",
                        "required": ["sector_type", "sender_id", "receiver_name", "receiver_phone", "pickup_lat", "pickup_long", "drop_lat", "drop_long"],
                        "properties": {
                            "reference": {"type": "string"},
                            "sector_type": {"type": "string", "enum": ["standard", "premium", "express", "fragile", "medical"]},
                            "sender_id": {"type": "integer"},
                            "receiver_name": {"type": "string"},
                            "receiver_phone": {"type": "string"},
                            "pickup_lat": {"type": "number", "format": "float"},
                            "pickup_long": {"type": "number", "format": "float"},
                            "drop_lat": {"type": "number", "format": "float"},
                            "drop_long": {"type": "number", "format": "float"}
                        }
                    }
                },
                "responses": {
                    "BadRequest": {
                        "description": "Bad request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "Unauthorized": {
                        "description": "Unauthorized",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "NotFound": {
                        "description": "Not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            },
            "paths": {
                "/smart_delivery/api/auth/login": {
                    "post": {
                        "tags": ["Authentication"],
                        "summary": "Authenticate user and get JWT token",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/LoginRequest"}
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Authentication successful",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/LoginResponse"}
                                    }
                                }
                            },
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/create": {
                    "post": {
                        "tags": ["Delivery"],
                        "summary": "Create a new delivery order",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DeliveryOrder"}
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Delivery order created",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "order_id": {"type": "integer"},
                                                "reference": {"type": "string"},
                                                "status": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/status/{order_id}": {
                    "get": {
                        "tags": ["Delivery"],
                        "summary": "Get delivery order status",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                                "description": "Delivery order ID"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Delivery status",
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "object"}
                                    }
                                }
                            },
                            "404": {"$ref": "#/components/responses/NotFound"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/assign": {
                    "post": {
                        "tags": ["Delivery"],
                        "summary": "Assign driver to delivery order",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["order_id"],
                                        "properties": {
                                            "order_id": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Driver assigned"},
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/delivery/validate/{order_id}": {
                    "post": {
                        "tags": ["Delivery"],
                        "summary": "Validate delivery conditions",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "otp_value": {"type": "string"},
                                            "signature": {"type": "string", "format": "base64"},
                                            "signature_filename": {"type": "string"},
                                            "photo_url": {"type": "string", "format": "uri"},
                                            "biometric_score": {"type": "number", "format": "float", "minimum": 0, "maximum": 1}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Validation result"},
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/location": {
                    "post": {
                        "tags": ["Driver"],
                        "summary": "Update driver GPS location",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["livreur_id", "lat", "long"],
                                        "properties": {
                                            "livreur_id": {"type": "integer"},
                                            "lat": {"type": "number", "format": "float"},
                                            "long": {"type": "number", "format": "float"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Location updated"},
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                }
            }
        }
    
    # ==================== DELIVERY ENDPOINTS ====================
    
    @http.route('/smart_delivery/api/delivery/create', type='http', auth='none', methods=['POST'], csrf=False)
    def create_delivery(self, **kwargs):
        """POST /smart_delivery/api/delivery/create - Crée une commande de livraison"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            
            # Validation des données
            required_fields = ['sector_type', 'sender_id', 'receiver_name', 'receiver_phone',
                             'pickup_lat', 'pickup_long', 'drop_lat', 'drop_long']
            for field in required_fields:
                if field not in data:
                    return self._json_response({'error': f'Champ requis manquant: {field}'}, 400)
            
            # Créer la commande
            order = request.env['delivery.order'].sudo().create({
                'reference': data.get('reference'),
                'sector_type': data['sector_type'],
                'sender_id': data['sender_id'],
                'receiver_name': data['receiver_name'],
                'receiver_phone': data['receiver_phone'],
                'pickup_lat': float(data['pickup_lat']),
                'pickup_long': float(data['pickup_long']),
                'drop_lat': float(data['drop_lat']),
                'drop_long': float(data['drop_long']),
            })
            
            response_data = {
                'success': True,
                'order_id': order.id,
                'reference': order.name,
                'status': order.status,
            }
            
            self._log_api_call('/smart_delivery/api/delivery/create', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur création livraison: {e}")
            error_response = {'error': str(e)}
            self._log_api_call('/smart_delivery/api/delivery/create', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/delivery/status/<int:order_id>', type='http', auth='none', methods=['GET'], csrf=False)
    def get_delivery_status(self, order_id, **kwargs):
        """GET /smart_delivery/api/delivery/status/<id> - Retourne le statut complet"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            order = request.env['delivery.order'].sudo().browse(order_id)
            if not order.exists():
                return self._json_response({'error': 'Commande non trouvée'}, 404)
            
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
    
    @http.route('/smart_delivery/api/delivery/assign', type='http', auth='none', methods=['POST'], csrf=False)
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
            
            order.assign_livreur()
            
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
    
    @http.route('/smart_delivery/api/delivery/validate/<int:order_id>', type='http', auth='none', methods=['POST'], csrf=False)
    def validate_delivery(self, order_id, **kwargs):
        """POST /smart_delivery/api/delivery/validate/<id> - Valide OTP, photo, signature, biométrie"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            order = request.env['delivery.order'].sudo().browse(order_id)
            
            if not order.exists():
                return self._json_response({'error': 'Commande non trouvée'}, 404)
            
            condition = order.condition_ids[:1]
            if not condition:
                condition = request.env['delivery.condition'].sudo().create({
                    'order_id': order.id,
                })
            
            # Valider OTP
            if 'otp_value' in data:
                if condition.otp_value == data['otp_value']:
                    condition.write({'otp_verified': True})
                else:
                    return self._json_response({'error': 'OTP invalide'}, 400)
            
            # Valider signature
            if 'signature' in data:
                condition.write({
                    'signature_file': data['signature'],
                    'signature_filename': data.get('signature_filename', 'signature.png'),
                })
            
            # Valider photo
            if 'photo_url' in data:
                condition.write({'photo_url': data['photo_url']})
            
            # Valider biométrie
            if 'biometric_score' in data:
                score = float(data['biometric_score'])
                if score < 0.7:
                    return self._json_response({'error': 'Score biométrique insuffisant'}, 400)
                condition.write({'biometric_score': score})
            
            # Valider toutes les conditions
            try:
                order.validate_conditions()
                response_data = {
                    'success': True,
                    'order_id': order.id,
                    'status': order.status,
                    'validated': True,
                }
            except ValidationError as ve:
                response_data = {
                    'success': False,
                    'order_id': order.id,
                    'status': order.status,
                    'validated': False,
                    'errors': str(ve),
                }
            
            self._log_api_call(f'/smart_delivery/api/delivery/validate/{order_id}', data, response_data)
            return self._json_response(response_data)
            
        except Exception as e:
            _logger.error(f"Erreur validation livraison: {e}")
            error_response = {'error': str(e)}
            self._log_api_call(f'/smart_delivery/api/delivery/validate/{order_id}', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
    
    @http.route('/smart_delivery/api/livreur/location', type='http', auth='none', methods=['POST'], csrf=False)
    def update_livreur_location(self, **kwargs):
        """POST /smart_delivery/api/livreur/location - Enregistre la position GPS du livreur"""
        auth_error = self._require_auth()
        if auth_error:
            return auth_error
        
        try:
            # Get JSON data from request body
            data = json.loads(request.httprequest.data.decode('utf-8')) if request.httprequest.data else {}
            livreur_id = data.get('livreur_id')
            lat = data.get('lat')
            long = data.get('long')
            
            if not all([livreur_id, lat, long]):
                return self._json_response({'error': 'livreur_id, lat et long requis'}, 400)
            
            livreur = request.env['delivery.livreur'].sudo().browse(livreur_id)
            if not livreur.exists():
                return self._json_response({'error': 'Livreur non trouvé'}, 404)
            
            livreur.write({
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
            error_response = {'error': str(e)}
            self._log_api_call('/smart_delivery/api/livreur/location', kwargs, error_response, 500, e)
            return self._json_response(error_response, 500)
