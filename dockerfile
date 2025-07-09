# Use the latest Python 3.12 image
FROM python:3.12-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy only essential files first (for efficient caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose Django's default port
EXPOSE 8000

# Run database migrations and start Gunicorn
CMD ["sh", "-c", "gunicorn --workers 4 --bind 0.0.0.0:8000 backend.wsgi:application"]