# R.A.I.D.  
### Respond | Assess | Investigate | Defend  
**Enterprise-Ready Incident Response Platform**

---

R.A.I.D. empowers teams to detect, investigate, and respond to cyber incidents using an AI-augmented analysis engine and structured response workflows.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/admiralarjun/raid.git
cd raid
```

### 2. Configure Docker Compose

Copy the sample file and modify it if needed:

```bash
cp sample-docker-compose.yml docker-compose.yml
```

---

### 3. Build & Start the Application

To build the images and launch the services:

```bash
docker compose up --build
```

If you are restarting without dependency changes:

```bash
docker compose up
```

---

### 4. Create a Django Superuser

Once the app is running, open a new terminal and run:

```bash
docker compose exec web python manage.py createsuperuser
```

Follow the prompts to create your admin account.

---

### 5. Access the Application

- **Incident Response Dashboard:** http://localhost:8000/
- **Admin Panel:** http://localhost:8000/admin/

---

## 🔌 Stopping the Application

Press `Ctrl+C` in the running terminal, or shut down the containers gracefully:

```bash
docker compose down
```

---

## ⚙️ Notes

- Requires Docker + Docker Compose installed.
- Rebuild the containers when modifying dependencies or Dockerfile:

```bash
docker compose up --build
```

- Customize environment variables and services inside `docker-compose.yml`.

---