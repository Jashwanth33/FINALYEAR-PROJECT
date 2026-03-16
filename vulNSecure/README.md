# vulNSecure Platform

## Project Structure
```
vulNSecure/
├── backend/                 # Node.js Express backend
│   ├── src/
│   │   ├── controllers/    # Route controllers
│   │   ├── models/         # Sequelize models
│   │   ├── routes/         # API routes
│   │   ├── middleware/     # Custom middleware
│   │   ├── services/       # Business logic
│   │   ├── utils/          # Utility functions
│   │   └── config/         # Configuration files
│   ├── tests/              # Backend tests
│   └── package.json
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API services
│   │   ├── hooks/          # Custom hooks
│   │   ├── utils/          # Utility functions
│   │   ├── context/        # React context
│   │   └── styles/         # CSS/styling
│   ├── public/             # Static assets
│   └── package.json
├── docker/                 # Docker configurations
├── docs/                   # Documentation
└── package.json           # Root package.json
```

## Quick Start

1. Install dependencies:
```bash
npm run install-all
```

2. Set up environment variables:
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

3. Start development servers:
```bash
npm run dev
```

## Features

- **Dark Web Monitoring**: AI-powered leak detection and classification
- **Vulnerability Scanning**: Network (Nmap) and Web App (OWASP ZAP) scanning
- **CVE Integration**: Real-time vulnerability data from NVD API
- **Risk Visualization**: Interactive dashboards and charts
- **PDF Reporting**: Comprehensive scan and leak reports
- **Collaboration**: Comments and task assignments
- **Security**: JWT authentication, RBAC, audit logging

## Technology Stack

### Backend
- Node.js with Express.js
- PostgreSQL with Sequelize ORM
- JWT Authentication
- Docker support

### Frontend
- React.js with React Router
- Tailwind CSS
- Framer Motion
- Lucide Icons
- React Hook Form

### Security Tools
- Nmap for network scanning
- OWASP ZAP for web app scanning
- Gemini AI for threat classification

## Development

### Backend Development
```bash
cd backend
npm run dev
```

### Frontend Development
```bash
cd frontend
npm start
```

### Testing
```bash
npm test
```

## Deployment

The platform supports Docker deployment with separate containers for frontend, backend, and database.

## License

MIT License - See LICENSE file for details
