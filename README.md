# Text Book Auth

Spring Boot Maven boilerplate with layered JWT authentication:

- Entity, repository, service, controller layers
- Spring Security `DaoAuthenticationProvider`
- JWT generation and validation
- Signup and login endpoints
- H2 database for local development

## Requirements

- Java 17+
- Maven 3.9+

## Run

```bash
mvn spring-boot:run
```

## Endpoints

### Signup

```http
POST /api/auth/signup
Content-Type: application/json

{
  "name": "Fahim Khan",
  "email": "fahim@example.com",
  "password": "password123"
}
```

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "fahim@example.com",
  "password": "password123"
}
```

Use the returned token as:

```http
Authorization: Bearer <token>
```

### Protected Example

```http
GET /api/users/me
Authorization: Bearer <token>
```
