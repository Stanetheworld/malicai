# Use an official Python image
FROM python:3.10

# Set the working directory inside the container
WORKDIR /app

# Copy all files from the repo to the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the required port
EXPOSE 10000

# Start FastAPI using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
