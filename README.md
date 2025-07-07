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

---

### 2. Configure Docker Compose

Copy the sample file and customize it for your environment:

```bash
cp sample-docker-compose.yml docker-compose.yml
```

---

### 3. Build & Start the Application

#### First time / after changes:
```bash
docker compose up --build
```

#### For restarting without rebuilding:
```bash
docker compose up
```

This will:
- Run DB migrations
- Collect static files
- Start the Django server on **http://localhost:8000/**

---

### 4. Create a Django Superuser

In a separate terminal tab:

```bash
docker compose exec web python manage.py createsuperuser
```

---

### 5. Access the Application

- **Incident Response Dashboard:** [http://localhost:8000/](http://localhost:8000/)
- **Admin Panel:** [http://localhost:8000/admin/](http://localhost:8000/admin/)

---

## 🔌 Stopping the Application

Press `Ctrl+C`, or stop the services gracefully:

```bash
docker compose down
```

---

## ⚙️ Notes

- Requires **Docker** + **Docker Compose** installed.
- Rebuild containers when dependencies or the Dockerfile changes:

```bash
docker compose up --build
```

- Customize environment variables in your `docker-compose.yml`.

---
