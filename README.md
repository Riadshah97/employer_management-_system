# Employer Management System

A Django REST API for managing employer information with JWT authentication.

## Features

### 1. Custom User Authentication
- Custom User model extending AbstractBaseUser and PermissionsMixin
- Token-based authentication using Simple JWT
- Login with email and password
- Endpoints for:
  - Sign Up (user registration)
  - Login (token generation)
  - Get Current User Profile

### 2. Employer Management
- Employer model with fields:
  - company_name
  - contact_person_name
  - email
  - phone_number
  - address
  - created_at
- Relationship: A User can have multiple Employers

### 3. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/signup/ | Register a new user |
| POST | /api/auth/login/ | Login and get JWT tokens |
| GET | /api/auth/profile/ | Get logged-in user's profile |
| POST | /api/employers/ | Create an Employer |
| GET | /api/employers/ | List all Employers for the logged-in user |
| GET | /api/employers/<id>/ | Retrieve a specific Employer |
| PUT | /api/employers/<id>/ | Update a specific Employer |
| DELETE | /api/employers/<id>/ | Delete a specific Employer |

### 4. Permissions
- Only authenticated users can access employers
- A user can only access, update, or delete their own employers

## Technology Stack
- Django 4.2.11
- Django REST Framework 3.14.0
- Simple JWT 5.3.0
- SQLite (default database)

## Setup and Installation

1. Clone the repository
```bash
git clone <repository-url>
cd employer_management-_system
```

2. Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Run migrations
```bash
python manage.py migrate
```

5. Create a superuser (admin)
```bash
python manage.py createsuperuser
```

6. Run the development server
```bash
python manage.py runserver
```

7. Access the API at http://127.0.0.1:8000/api/

## API Usage Examples

### Register a new user
```bash
curl -X POST http://127.0.0.1:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "username": "user1", "password": "password123", "confirm_password": "password123"}'
```

### Login
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

### Create an Employer (with authentication)
```bash
curl -X POST http://127.0.0.1:8000/api/employers/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-access-token>" \
  -d '{"company_name": "Example Corp", "contact_person_name": "John Doe", "email": "contact@example.com", "phone_number": "123-456-7890", "address": "123 Main St"}'
```

## Project Structure
- `employer_project/` - Main project directory
- `employer_app/` - Django application with models, views, and serializers
- `employer_app/models.py` - Contains User and Employer models
- `employer_app/views.py` - API views and endpoints
- `employer_app/serializers.py` - Serializers for models
- `employer_app/permissions.py` - Custom permissions

## Security Features
- JWT token-based authentication
- Custom permissions for data access control
- Password validation and hashing
- CSRF protection (Django built-in)


## Postman Collection

Endpoint: POST /api/auth/signup/
Endpoint: POST /api/auth/login/
Endpoint: GET /api/auth/profile/

Endpoint: POST /api/employers/
Endpoint: GET /api/employers/
Endpoint: GET /api/employers/<id>/
Endpoint: PUT /api/employers/<id>/
Endpoint: DELETE /api/employers/<id>/
