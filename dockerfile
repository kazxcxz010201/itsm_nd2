# Use an official Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy your Flask app and templates into the container
COPY myapp/ .

# Install dependencies 
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Flask will run on
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Command to run the Flask app
CMD ["python", "app.py"]

