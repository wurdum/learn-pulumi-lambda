# AWS Lambda with API Gateway and Auth0 Authentication

This Pulumi application deploys an AWS Lambda function with API Gateway integration, secured by Auth0 authentication.

## Prerequisites

- Node.js (use nvm for version management)
- Pulumi CLI
- AWS CLI configured
- Auth0 account

## Auth0 Configuration

Collect the following credentials from your Auth0 dashboard:

- **Issuer**: Your Auth0 domain (e.g., `https://dev-1234567890.us.auth0.com/`)
- **Audience**: API identifier (e.g., `https://dev-1234567890.us.auth0.com/api/v2/`)
- **JWKS URI**: JSON Web Key Set endpoint (e.g., `https://dev-1234567890.us.auth0.com/.well-known/jwks.json`)

## Installation

1. Set the Node.js version:
```bash
nvm use
```

2. Install dependencies:
```bash
npm install
```

3. Configure Pulumi with Auth0 credentials:
```bash
pulumi config set --secret issuer <your-auth0-issuer>
pulumi config set --secret audience <your-auth0-audience>
pulumi config set --secret jwksUri <your-auth0-jwks-uri>
```

## Deployment

Deploy the stack:

```bash
pulumi up -y
```

If you're using aws-vault:
```bash
aws-vault exec personal -- pulumi up -y
```

To destroy the stack:

```bash
pulumi down -y
```

## API Endpoints

- `GET /`: Serves static content
- `GET /date`: Returns current timestamp (requires JWT authentication)

## Security

The `/date` endpoint is protected with Auth0 JWT authentication. Include a valid Bearer token in the Authorization header to access it:

```
Authorization: Bearer <your-jwt-token>
```

To get a token, you can use the Auth0 Management API test token.

## License

MIT
