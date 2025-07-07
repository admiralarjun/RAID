FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project code
COPY . .

# Collect static files and apply migrations at build
RUN python manage.py collectstatic --noinput
RUN python manage.py migrate --noinput

# Expose port 8000 for dev server
EXPOSE 8000

# Run the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
