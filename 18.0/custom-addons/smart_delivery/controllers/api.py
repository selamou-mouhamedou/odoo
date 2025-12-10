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
        """Get user type: 'livreur' or 'other'"""
        if not user:
            return 'other'
        # Check if user has a livreur record
        livreur = request.env['delivery.livreur'].sudo().search([('user_id', '=', user.id)], limit=1)
        return 'livreur' if livreur else 'other'
    
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
                "/smart_delivery/api/auth/logout": {
                    "post": {
                        "tags": ["Authentication"],
                        "summary": "Logout user and invalidate session",
                        "description": "Logs out the current user. The client should discard the JWT token after this call.",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Logout successful",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "message": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            },
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
                "/smart_delivery/api/livreur/location": {
                    "post": {
                        "tags": ["Driver"],
                        "summary": "Update my GPS location (for authenticated driver)",
                        "description": "Update GPS location for the authenticated driver. The driver is auto-detected from JWT token.",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["lat", "long"],
                                        "properties": {
                                            "lat": {"type": "number", "format": "float", "example": 33.5731},
                                            "long": {"type": "number", "format": "float", "example": -7.5898}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Location updated successfully"},
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "401": {"$ref": "#/components/responses/Unauthorized"},
                            "403": {"description": "Not a driver - access denied"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/orders/{order_id}/deliver": {
                    "post": {
                        "tags": ["Driver"],
                        "summary": "Complete a delivery with validation",
                        "description": "Validate delivery conditions (OTP, signature, photo, biometric) based on order requirements and mark order as delivered. The driver is auto-detected from JWT token. Only orders assigned to the authenticated driver can be completed.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                                "description": "Order ID to deliver"
                            }
                        ],
                        "requestBody": {
                            "required": True,
                            "description": "Validation data based on order requirements",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "otp_value": {
                                                "type": "string",
                                                "description": "6-digit OTP code (required if otp_required is true)",
                                                "example": "123456"
                                            },
                                            "signature": {
                                                "type": "string",
                                                "format": "base64",
                                                "description": "Base64 encoded signature image (required if signature_required is true)"
                                            },
                                            "signature_filename": {
                                                "type": "string",
                                                "description": "Signature filename (optional, defaults to signature.png)",
                                                "example": "signature.png"
                                            },
                                            "photo_url": {
                                                "type": "string",
                                                "format": "uri",
                                                "description": "URL of delivery proof photo (required if photo_required is true)",
                                                "example": "https://storage.example.com/photos/delivery_123.jpg"
                                            },
                                            "biometric_score": {
                                                "type": "number",
                                                "format": "float",
                                                "minimum": 0,
                                                "maximum": 1,
                                                "description": "Biometric verification score (required if biometric_required is true, minimum 0.7)",
                                                "example": 0.85
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Delivery completed successfully",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "order_id": {"type": "integer"},
                                                "reference": {"type": "string"},
                                                "previous_status": {"type": "string"},
                                                "status": {"type": "string"},
                                                "message": {"type": "string"},
                                                "validation": {"type": "object"},
                                                "billing": {"type": "object"}
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Validation failed - missing or invalid data",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "error": {"type": "string"},
                                                "code": {"type": "string"},
                                                "validation_errors": {
                                                    "type": "array",
                                                    "items": {"type": "string"}
                                                },
                                                "requirements": {"type": "object"}
                                            }
                                        }
                                    }
                                }
                            },
                            "403": {"description": "Order not assigned to this driver"},
                            "404": {"$ref": "#/components/responses/NotFound"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/orders/{order_id}/start": {
                    "post": {
                        "tags": ["Driver"],
                        "summary": "Start a delivery (change status from assigned to on_way)",
                        "description": "Allows a driver to start a delivery. Changes the order status from 'assigned' to 'on_way'. The driver is auto-detected from JWT token. Only orders assigned to the authenticated driver can be started.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                                "description": "Order ID to start"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Delivery started successfully",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "order_id": {"type": "integer"},
                                                "reference": {"type": "string"},
                                                "previous_status": {"type": "string"},
                                                "status": {"type": "string"},
                                                "message": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {"$ref": "#/components/responses/BadRequest"},
                            "403": {
                                "description": "Order not assigned to this driver",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Error"}
                                    }
                                }
                            },
                            "404": {"$ref": "#/components/responses/NotFound"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/my-orders": {
                    "get": {
                        "tags": ["Driver"],
                        "summary": "Get my orders (for authenticated driver)",
                        "description": "Returns all delivery orders assigned to the authenticated driver. The driver is auto-detected from JWT token. Returns full details including conditions, validation status, and billing information.",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "status",
                                "in": "query",
                                "required": False,
                                "schema": {
                                    "type": "string",
                                    "enum": ["draft", "assigned", "on_way", "delivered", "failed"]
                                },
                                "description": "Filter orders by status"
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "integer", "default": 50},
                                "description": "Maximum number of orders to return"
                            },
                            {
                                "name": "offset",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "integer", "default": 0},
                                "description": "Number of orders to skip"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "List of orders assigned to the driver",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "livreur": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"},
                                                        "phone": {"type": "string"},
                                                        "vehicle_type": {"type": "string"},
                                                        "availability": {"type": "boolean"},
                                                        "rating": {"type": "number"}
                                                    }
                                                },
                                                "pagination": {
                                                    "type": "object",
                                                    "properties": {
                                                        "total": {"type": "integer"},
                                                        "limit": {"type": "integer"},
                                                        "offset": {"type": "integer"}
                                                    }
                                                },
                                                "orders_count": {"type": "integer"},
                                                "orders": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id": {"type": "integer"},
                                                            "reference": {"type": "string"},
                                                            "status": {"type": "string"},
                                                            "sector_type": {"type": "string"},
                                                            "sender": {"type": "object"},
                                                            "receiver": {"type": "object"},
                                                            "pickup": {"type": "object"},
                                                            "drop": {"type": "object"},
                                                            "distance_km": {"type": "number"},
                                                            "conditions": {"type": "object"},
                                                            "validation": {"type": "object"},
                                                            "billing": {"type": "object"}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "404": {"$ref": "#/components/responses/NotFound"},
                            "401": {"$ref": "#/components/responses/Unauthorized"}
                        }
                    }
                },
                "/smart_delivery/api/livreur/stats": {
                    "get": {
                        "tags": ["Driver"],
                        "summary": "Get delivery statistics for the authenticated driver",
                        "description": "Returns delivery statistics including today's deliveries, in progress, delivered, and failed counts. The driver is auto-detected from JWT token.",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "Driver statistics",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "livreur": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "name": {"type": "string"}
                                                    }
                                                },
                                                "stats": {
                                                    "type": "object",
                                                    "properties": {
                                                        "today": {"type": "integer", "description": "Number of deliveries created today"},
                                                        "in_progress": {"type": "integer", "description": "Number of deliveries in progress (assigned or on_way)"},
                                                        "delivered": {"type": "integer", "description": "Total number of delivered orders"},
                                                        "failed": {"type": "integer", "description": "Total number of failed orders"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {"$ref": "#/components/responses/Unauthorized"},
                            "403": {"description": "Not a driver - access denied"}
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
    
    @http.route('/smart_delivery/api/delivery/status/<int:order_id>', type='http', auth='public', methods=['GET'], csrf=False)
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
