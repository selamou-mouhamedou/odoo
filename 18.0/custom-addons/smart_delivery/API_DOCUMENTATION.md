# Smart Delivery API Documentation

## Overview

The Smart Delivery API provides REST endpoints for managing delivery orders, tracking status, assigning delivery drivers (livreurs), and validating delivery conditions (OTP, signature, photo, biometric).

**Base URL**: `http://localhost:8069` (or your Odoo server URL)

---

## Authentication

All endpoints require authentication. The API supports two authentication methods:

### 1. Session Authentication (Current Implementation)
- Uses Odoo's built-in session authentication
- Requires a valid Odoo user session
- Set `auth='user'` in the route decorator

### 2. API Key / JWT (Planned)
- Header: `X-API-Key: your-api-key`
- Or: `Authorization: Bearer your-jwt-token`
- Currently, the code structure is ready but needs JWT library implementation

**Note**: For now, you need to be logged into Odoo to use the API.

---

## API Endpoints

### 1. Create Delivery Order

**Endpoint**: `POST /smart_delivery/api/delivery/create`

**Description**: Creates a new delivery order with pickup and drop-off locations.

**Request Body** (JSON):
```json
{
  "reference": "REF-12345",           // Optional: External reference
  "sector_type": "standard",          // Required: standard|premium|express|fragile|medical
  "sender_id": 1,                     // Required: Partner ID (res.partner)
  "receiver_name": "John Doe",        // Required: Receiver name
  "receiver_phone": "+1234567890",    // Required: Receiver phone
  "pickup_lat": 45.5017,              // Required: Pickup latitude
  "pickup_long": -73.5673,            // Required: Pickup longitude
  "drop_lat": 45.5088,                // Required: Drop-off latitude
  "drop_long": -73.5878               // Required: Drop-off longitude
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "order_id": 42,
  "reference": "DEL00042",
  "status": "draft"
}
```

**Error Response** (400 Bad Request):
```json
{
  "error": "Champ requis manquant: sector_type"
}
```

**Example cURL**:
```bash
curl -X POST http://localhost:8069/smart_delivery/api/delivery/create \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=your_session_id" \
  -d '{
    "sector_type": "express",
    "sender_id": 1,
    "receiver_name": "Jane Smith",
    "receiver_phone": "+1234567890",
    "pickup_lat": 45.5017,
    "pickup_long": -73.5673,
    "drop_lat": 45.5088,
    "drop_long": -73.5878
  }'
```

---

### 2. Get Delivery Status

**Endpoint**: `GET /smart_delivery/api/delivery/status/<order_id>`

**Description**: Retrieves complete status information for a delivery order.

**URL Parameters**:
- `order_id` (integer): The delivery order ID

**Response** (200 OK):
```json
{
  "order_id": 42,
  "reference": "DEL00042",
  "status": "assigned",
  "sector_type": "express",
  "sender": {
    "id": 1,
    "name": "Sender Company"
  },
  "receiver": {
    "name": "Jane Smith",
    "phone": "+1234567890"
  },
  "pickup": {
    "lat": 45.5017,
    "long": -73.5673
  },
  "drop": {
    "lat": 45.5088,
    "long": -73.5878
  },
  "livreur": {
    "id": 5,
    "name": "Driver Name"
  },
  "distance_km": 12.5,
  "conditions": {
    "otp_required": true,
    "signature_required": true,
    "photo_required": false,
    "biometric_required": false
  },
  "validation": {
    "otp_verified": false,
    "signature_provided": false,
    "photo_provided": false,
    "biometric_score": null,
    "validated": false
  }
}
```

**Error Response** (404 Not Found):
```json
{
  "error": "Commande non trouvée"
}
```

**Example cURL**:
```bash
curl -X GET http://localhost:8069/smart_delivery/api/delivery/status/42 \
  -H "Cookie: session_id=your_session_id"
```

---

### 3. Assign Delivery Driver

**Endpoint**: `POST /smart_delivery/api/delivery/assign`

**Description**: Triggers automatic dispatching to assign the best available driver to a delivery order.

**Request Body** (JSON):
```json
{
  "order_id": 42
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "order_id": 42,
  "livreur_id": 5,
  "livreur_name": "Driver Name",
  "status": "assigned"
}
```

**Response** (if no driver available):
```json
{
  "success": true,
  "order_id": 42,
  "livreur_id": null,
  "livreur_name": null,
  "status": "draft"
}
```

**Example cURL**:
```bash
curl -X POST http://localhost:8069/smart_delivery/api/delivery/assign \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=your_session_id" \
  -d '{
    "order_id": 42
  }'
```

**Dispatching Algorithm**:
The system automatically selects the best driver based on:
- Distance to pickup point (50% weight)
- Driver rating (20% weight)
- Rest time (10% weight)
- Vehicle speed type (20% weight)

---

### 4. Validate Delivery Conditions

**Endpoint**: `POST /smart_delivery/api/delivery/validate/<order_id>`

**Description**: Validates delivery conditions (OTP, signature, photo, biometric) and marks delivery as complete if all required conditions are met.

**URL Parameters**:
- `order_id` (integer): The delivery order ID

**Request Body** (JSON):
```json
{
  "otp_value": "123456",                    // Optional: OTP code if required
  "signature": "base64_encoded_image",      // Optional: Signature image (base64)
  "signature_filename": "signature.png",    // Optional: Signature filename
  "photo": "base64_encoded_image",          // Optional: Delivery photo (base64)
  "photo_filename": "delivery_photo.jpg",   // Optional: Photo filename
  "biometric_score": 0.85                    // Optional: Biometric verification score (0-1)
}
```

**Response** (200 OK - Success):
```json
{
  "success": true,
  "order_id": 42,
  "status": "delivered",
  "validated": true
}
```

**Response** (200 OK - Validation Failed):
```json
{
  "success": false,
  "order_id": 42,
  "status": "on_way",
  "validated": false,
  "errors": "OTP non vérifié\nSignature manquante"
}
```

**Error Response** (400 Bad Request):
```json
{
  "error": "OTP invalide"
}
```

**Example cURL**:
```bash
curl -X POST http://localhost:8069/smart_delivery/api/delivery/validate/42 \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=your_session_id" \
  -d '{
    "otp_value": "123456",
    "signature": "iVBORw0KGgoAAAANSUhEUgAA...",
    "signature_filename": "signature.png",
    "photo": "iVBORw0KGgoAAAANSUhEUgAA...",
    "photo_filename": "delivery_photo.jpg",
    "biometric_score": 0.92
  }'
```

**Validation Rules**:
- OTP: Must match the generated OTP for the order
- Signature: Base64 encoded image
- Photo: URL to the delivery photo
- Biometric: Score must be >= 0.7 to be accepted

---

### 5. Update Driver Location

**Endpoint**: `POST /smart_delivery/api/livreur/location`

**Description**: Updates the GPS location of a delivery driver in real-time.

**Request Body** (JSON):
```json
{
  "livreur_id": 5,      // Required: Driver ID
  "lat": 45.5017,       // Required: Current latitude
  "long": -73.5673      // Required: Current longitude
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "livreur_id": 5,
  "lat": 45.5017,
  "long": -73.5673
}
```

**Error Response** (404 Not Found):
```json
{
  "error": "Livreur non trouvé"
}
```

**Example cURL**:
```bash
curl -X POST http://localhost:8069/smart_delivery/api/livreur/location \
  -H "Content-Type: application/json" \
  -H "Cookie: session_id=your_session_id" \
  -d '{
    "livreur_id": 5,
    "lat": 45.5017,
    "long": -73.5673
  }'
```

**Use Case**: 
This endpoint should be called periodically (e.g., every 30 seconds) from a mobile app to track driver location in real-time.

---

## Status Codes

- **200 OK**: Request successful
- **400 Bad Request**: Invalid request data or missing required fields
- **404 Not Found**: Resource (order, driver) not found
- **500 Internal Server Error**: Server error

---

## Delivery Order Statuses

- `draft`: Order created, not yet assigned
- `assigned`: Driver assigned to the order
- `on_way`: Driver is en route to delivery location
- `delivered`: Delivery completed successfully
- `failed`: Delivery failed

---

## Sector Types

- `standard`: Standard delivery
- `premium`: Premium delivery
- `express`: Express delivery
- `fragile`: Fragile items
- `medical`: Medical supplies

---

## API Logging

All API calls are automatically logged to the `api.log` model with:
- Client ID (from `X-Client-ID` header)
- Endpoint
- Request payload
- Response data
- Status code
- Error messages (if any)

**To view logs**: Go to Smart Delivery > Journaux API

---

## Example Workflow

### Complete Delivery Flow:

1. **Create Order**:
```bash
POST /smart_delivery/api/delivery/create
{
  "sector_type": "express",
  "sender_id": 1,
  "receiver_name": "John Doe",
  "receiver_phone": "+1234567890",
  "pickup_lat": 45.5017,
  "pickup_long": -73.5673,
  "drop_lat": 45.5088,
  "drop_long": -73.5878
}
```

2. **Assign Driver**:
```bash
POST /smart_delivery/api/delivery/assign
{
  "order_id": 42
}
```

3. **Update Driver Location** (periodically):
```bash
POST /smart_delivery/api/livreur/location
{
  "livreur_id": 5,
  "lat": 45.5050,
  "long": -73.5700
}
```

4. **Check Status**:
```bash
GET /smart_delivery/api/delivery/status/42
```

5. **Validate Delivery**:
```bash
POST /smart_delivery/api/delivery/validate/42
{
  "otp_value": "123456",
  "signature": "base64_image",
  "photo": "base64_image"
}
```

---

## Python Client Example

```python
import requests
import json

BASE_URL = "http://localhost:8069"
SESSION_ID = "your_session_id"

# Create delivery
response = requests.post(
    f"{BASE_URL}/smart_delivery/api/delivery/create",
    json={
        "sector_type": "express",
        "sender_id": 1,
        "receiver_name": "John Doe",
        "receiver_phone": "+1234567890",
        "pickup_lat": 45.5017,
        "pickup_long": -73.5673,
        "drop_lat": 45.5088,
        "drop_long": -73.5878
    },
    cookies={"session_id": SESSION_ID}
)
order = response.json()
order_id = order["order_id"]

# Assign driver
requests.post(
    f"{BASE_URL}/smart_delivery/api/delivery/assign",
    json={"order_id": order_id},
    cookies={"session_id": SESSION_ID}
)

# Check status
status = requests.get(
    f"{BASE_URL}/smart_delivery/api/delivery/status/{order_id}",
    cookies={"session_id": SESSION_ID}
).json()
print(status)
```

---

## JavaScript/Node.js Example

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8069';
const SESSION_ID = 'your_session_id';

// Create delivery
async function createDelivery() {
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
      headers: { 'Content-Type': 'application/json' },
      withCredentials: true
    }
  );
  
  return response.data;
}

// Get status
async function getStatus(orderId) {
  const response = await axios.get(
    `${BASE_URL}/smart_delivery/api/delivery/status/${orderId}`,
    { withCredentials: true }
  );
  
  return response.data;
}
```

---

## Notes

1. **CSRF Protection**: Currently disabled (`csrf=False`) for API endpoints. In production, implement proper CSRF protection or use API keys.

2. **Authentication**: Currently uses Odoo session authentication. For mobile apps or external systems, implement JWT authentication.

3. **Error Handling**: All endpoints return JSON error responses with descriptive messages.

4. **Logging**: All API calls are logged for debugging and auditing purposes.

5. **Permissions**: Uses `sudo()` for database operations. Ensure proper access rights are configured in `ir.model.access.csv`.

---

## Future Enhancements

- JWT token authentication
- Webhook support for status updates
- Batch operations (create multiple orders)
- Driver availability endpoints
- Route optimization
- Real-time notifications via WebSockets
