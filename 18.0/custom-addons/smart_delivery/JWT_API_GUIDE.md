# Smart Delivery JWT API - Quick Start Guide

## Overview

The Smart Delivery API now supports **JWT (JSON Web Token) authentication**, allowing external applications and mobile apps to authenticate without needing an Odoo session.

## Features

✅ **JWT Authentication** - Secure token-based authentication  
✅ **Swagger/OpenAPI Documentation** - Interactive API documentation  
✅ **Login Endpoint** - Get JWT tokens for API access  
✅ **Backward Compatible** - Still supports Odoo session authentication  

---

## Installation

### 1. Install Python Dependencies

The module requires `PyJWT` and `cryptography`. Install them:

```bash
pip install PyJWT cryptography
```

Or if using Odoo's virtual environment:

```bash
./venv/bin/pip install PyJWT cryptography
```

### 2. Upgrade the Module

```bash
./venv/bin/python ./odoo/odoo-bin -c odoo.conf -u smart_delivery --stop-after-init
```

---

## API Endpoints

### 1. Login (Get JWT Token)

**Endpoint**: `POST /smart_delivery/api/auth/login`

**Request**:
```json
{
  "login": "admin",
  "password": "admin"
}
```

**Response**:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 2,
    "name": "Administrator",
    "login": "admin"
  },
  "expires_in": 86400
}
```

**cURL Example**:
```bash
curl -X POST http://localhost:8069/smart_delivery/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "login": "admin",
    "password": "admin"
  }'
```

---

### 2. Using JWT Token

After getting the token, include it in the `Authorization` header:

```bash
curl -X POST http://localhost:8069/smart_delivery/api/delivery/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
  -d '{
    "sector_type": "express",
    "sender_id": 1,
    "receiver_name": "John Doe",
    "receiver_phone": "+1234567890",
    "pickup_lat": 45.5017,
    "pickup_long": -73.5673,
    "drop_lat": 45.5088,
    "drop_long": -73.5878
  }'
```

---

## Swagger Documentation

### Access Swagger UI

Open your browser and navigate to:

```
http://localhost:8069/smart_delivery/api/docs/ui
```

This will show an interactive Swagger UI where you can:
- View all API endpoints
- See request/response schemas
- Test endpoints directly from the browser
- Authenticate with JWT tokens

### Access OpenAPI JSON

Get the raw OpenAPI specification:

```
http://localhost:8069/smart_delivery/api/docs
```

---

## Complete Example Workflow

### Step 1: Login and Get Token

```python
import requests

BASE_URL = "http://localhost:8069"

# Login
response = requests.post(
    f"{BASE_URL}/smart_delivery/api/auth/login",
    json={
        "login": "admin",
        "password": "admin"
    }
)

data = response.json()
token = data["token"]
print(f"Token: {token}")
```

### Step 2: Use Token for API Calls

```python
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Create delivery
response = requests.post(
    f"{BASE_URL}/smart_delivery/api/delivery/create",
    headers=headers,
    json={
        "sector_type": "express",
        "sender_id": 1,
        "receiver_name": "John Doe",
        "receiver_phone": "+1234567890",
        "pickup_lat": 45.5017,
        "pickup_long": -73.5673,
        "drop_lat": 45.5088,
        "drop_long": -73.5878
    }
)

order = response.json()
print(f"Order ID: {order['order_id']}")
```

### Step 3: Check Status

```python
order_id = order['order_id']

response = requests.get(
    f"{BASE_URL}/smart_delivery/api/delivery/status/{order_id}",
    headers=headers
)

status = response.json()
print(status)
```

---

## JavaScript/Node.js Example

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8069';

// Step 1: Login
async function login(username, password) {
  const response = await axios.post(
    `${BASE_URL}/smart_delivery/api/auth/login`,
    { login: username, password: password }
  );
  return response.data.token;
}

// Step 2: Use token
async function createDelivery(token) {
  const response = await axios.post(
    `${BASE_URL}/smart_delivery/api/delivery/create`,
    {
      sector_type: 'express',
      sender_id: 1,
      receiver_name: 'John Doe',
      receiver_phone: '+1234567890',
      pickup_lat: 45.5017,
      pickup_long: -73.5673,
      drop_lat: 45.5088,
      drop_long: -73.5878
    },
    {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    }
  );
  return response.data;
}

// Usage
(async () => {
  const token = await login('admin', 'admin');
  const order = await createDelivery(token);
  console.log('Order created:', order);
})();
```

---

## Token Expiration

- **Default expiration**: 24 hours
- **Token format**: JWT (JSON Web Token)
- **Algorithm**: HS256

When a token expires, you'll get a 401 Unauthorized response. Simply login again to get a new token.

---

## Security Notes

⚠️ **Important**: The JWT secret key is currently hardcoded. For production:

1. **Change the secret key** in `utils/jwt_auth.py`:
   ```python
   SECRET_KEY = 'your-very-secure-random-secret-key-here'
   ```

2. **Use environment variables** or Odoo configuration to store the secret key

3. **Use HTTPS** in production to protect tokens in transit

4. **Implement token refresh** mechanism for better security

---

## Error Responses

### 401 Unauthorized
```json
{
  "error": "Authentication required",
  "code": "AUTH_REQUIRED"
}
```

### 401 Invalid Credentials
```json
{
  "error": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

### 400 Bad Request
```json
{
  "error": "login and password are required",
  "code": "MISSING_CREDENTIALS"
}
```

---

## All Available Endpoints

1. **POST** `/smart_delivery/api/auth/login` - Login and get JWT token
2. **POST** `/smart_delivery/api/delivery/create` - Create delivery order
3. **GET** `/smart_delivery/api/delivery/status/<id>` - Get delivery status
4. **POST** `/smart_delivery/api/delivery/assign` - Assign driver
5. **POST** `/smart_delivery/api/delivery/validate/<id>` - Validate delivery
6. **POST** `/smart_delivery/api/livreur/location` - Update driver location
7. **GET** `/smart_delivery/api/docs` - OpenAPI JSON specification
8. **GET** `/smart_delivery/api/docs/ui` - Swagger UI interface

---

## Testing with Postman

1. **Import Collection**: Use the OpenAPI spec from `/smart_delivery/api/docs`

2. **Set up Authentication**:
   - Create a request to `/smart_delivery/api/auth/login`
   - Copy the token from the response
   - Go to Collection settings → Authorization
   - Select "Bearer Token" and paste your token

3. **Test Endpoints**: All requests will now include the JWT token automatically

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'jwt'"

**Solution**: Install PyJWT
```bash
pip install PyJWT cryptography
```

### "Authentication required" error

**Solution**: 
- Make sure you're including the `Authorization: Bearer <token>` header
- Check if your token has expired (login again)
- Verify the token is correctly formatted

### Token expires too quickly

**Solution**: Modify `TOKEN_EXPIRY_HOURS` in `utils/jwt_auth.py`

---

## Next Steps

- ✅ JWT authentication implemented
- ✅ Swagger documentation available
- ✅ Login endpoint working
- 🔄 Token refresh endpoint (future enhancement)
- 🔄 Role-based access control (future enhancement)

Enjoy using the Smart Delivery API! 🚀
