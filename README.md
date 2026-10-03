# JWKS Server

CSCE 3550 Project 1

This project implements a basic JWKS server using Python and Flask.

## Features

- RSA key generation
- Unique key IDs (`kid`)
- Key expiration
- JWKS endpoint
- JWT authentication endpoint
- Expired JWT support
- Automated tests

## Endpoints

### JWKS
GET /.well-known/jwks.json

### Authentication
POST /auth

### Expired Authentication
POST /auth?expired=true

## Running the Project

Install dependencies:

pip install -r requirements.txt

Run the server:

python app.py

The server runs on port 8080.

## Testing

Run:

pytest --cov=app

Results:
- 8 tests passed
- 97% test coverage
- Gradebot score: 98.57%

## AI Use

I used ChatGPT to help explain the assignment requirements, troubleshoot Python and Flask setup, debug the JWKS server, create and review test cases, and understand gradebot errors. I also used ChatGPT to help interpret terminal errors and guide the setup process step by step.
