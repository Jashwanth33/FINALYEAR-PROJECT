# vulNSecure Deployment Guide

## Option 1: Render (Recommended - Free Forever)

### Step 1: Create Render Account
1. Go to https://render.com
2. Click "Get Started for Free"
3. Sign up with GitHub

### Step 2: Deploy Backend
1. Click "New +" → "Web Service"
2. Connect your GitHub repository
3. Configure:
   ```
   Name: vulnsecure-backend
   Region: Choose closest to you
   Branch: master
   Root Directory: vulNSecure/backend
   Runtime: Node
   Build Command: npm install
   Start Command: node src/server.js
   Plan: Free
   ```
4. Add Environment Variables:
   ```
   NODE_ENV=production
   PORT=5001
   JWT_SECRET=your-super-secret-key-here
   ```
5. Click "Create Web Service"

### Step 3: Deploy Frontend
1. Click "New +" → "Static Site"
2. Connect same GitHub repository
3. Configure:
   ```
   Name: vulnsecure-frontend
   Branch: master
   Root Directory: vulNSecure/frontend
   Build Command: npm install && npm run build
   Publish Directory: build
   ```
4. Add Environment Variable:
   ```
   REACT_APP_API_URL=https://vulnsecure-backend.onrender.com/api
   ```
5. Click "Create Static Site"

### Step 4: Update Frontend API URL
In `vulNSecure/frontend/src/services/api.js`:
```javascript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://vulnsecure-backend.onrender.com/api';
```

### Step 5: Access Your App
- Frontend: https://vulnsecure-frontend.onrender.com
- Backend: https://vulnsecure-backend.onrender.com

---

## Option 2: Railway ($5 Free Credit/Month)

### Step 1: Create Railway Account
1. Go to https://railway.app
2. Sign up with GitHub

### Step 2: Deploy
1. Click "New Project"
2. Select "Deploy from GitHub repo"
3. Choose your repository
4. Railway auto-detects Node.js and deploys

### Step 3: Add Environment Variables
In Railway dashboard:
```
NODE_ENV=production
PORT=5001
JWT_SECRET=your-secret-key
```

---

## Option 3: Fly.io (Free Forever)

### Step 1: Install Fly CLI
```bash
# Windows
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"

# Mac/Linux
curl -L https://fly.io/install.sh | sh
```

### Step 2: Login
```bash
fly auth login
```

### Step 3: Create Dockerfile
Create `vulNSecure/Dockerfile`:
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy backend
COPY vulNSecure/backend/package*.json ./backend/
RUN cd backend && npm install

COPY vulNSecure/backend ./backend

# Copy frontend
COPY vulNSecure/frontend/package*.json ./frontend/
RUN cd frontend && npm install

COPY vulNSecure/frontend ./frontend
RUN cd frontend && npm run build

# Install serve for frontend
RUN npm install -g serve

# Expose ports
EXPOSE 5001 3000

# Start script
CMD cd /app/backend && node src/server.js & serve -s frontend/build -l 3000
```

### Step 4: Deploy
```bash
fly launch
fly deploy
```

---

## Option 4: Oracle Cloud (Most Powerful - Free Forever)

### Step 1: Create Oracle Cloud Account
1. Go to https://cloud.oracle.com
2. Click "Start for Free"
3. Sign up (requires credit card for verification, won't be charged)

### Step 2: Create VM Instance
1. Go to Compute → Instances
2. Click "Create Instance"
3. Configure:
   ```
   Name: vulnsecure-server
   Image: Ubuntu 22.04
   Shape: VM.Standard.A1.Flex (ARM - Always Free)
   CPUs: 4
   Memory: 24 GB
   ```
4. Add SSH key
5. Click "Create"

### Step 3: Connect to Server
```bash
ssh -i your-key.pem ubuntu@your-server-ip
```

### Step 4: Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install Nginx
sudo apt install -y nginx

# Install PM2
sudo npm install -g pm2
```

### Step 5: Deploy Application
```bash
# Clone repository
git clone https://github.com/Jashwanth33/FINALYEAR-PROJECT.git
cd FINALYEAR-PROJECT

# Install backend dependencies
cd vulNSecure/backend
npm install

# Install frontend dependencies and build
cd ../frontend
npm install
npm run build

# Start with PM2
cd ../backend
pm2 start src/server.js --name vulnsecure

# Save PM2 config
pm2 save
pm2 startup
```

### Step 6: Configure Nginx
```bash
sudo nano /etc/nginx/sites-available/vulnsecure
```

Add:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /api {
        proxy_pass http://localhost:5001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location / {
        root /home/ubuntu/FINALYEAR-PROJECT/vulNSecure/frontend/build;
        try_files $uri $uri/ /index.html;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/vulnsecure /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Add SSL (Free)
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## Quick Start (Easiest)

### For Render:
1. Go to https://render.com
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Select your repo
5. Set root directory to `vulNSecure/backend`
6. Set start command to `node src/server.js`
7. Click "Create Web Service"
8. Repeat for frontend (Static Site)

### Your app will be live at:
- Backend: https://your-app.onrender.com
- Frontend: https://your-frontend.onrender.com

---

## Environment Variables Needed

| Variable | Description | Example |
|----------|-------------|---------|
| NODE_ENV | Environment | production |
| PORT | Server port | 5001 |
| JWT_SECRET | Secret key | your-secret-key |
| DB_HOST | Database host | localhost |
| DB_NAME | Database name | vulnsecure |

---

## Troubleshooting

### If app crashes on Render:
- Check logs in Render dashboard
- Ensure all dependencies are in package.json
- Set correct start command

### If frontend can't connect to backend:
- Update REACT_APP_API_URL to backend URL
- Ensure CORS is enabled in backend

### If database connection fails:
- Use SQLite (default) or set up PostgreSQL
- Check database environment variables

---

**Need help? Contact support or check documentation.**
