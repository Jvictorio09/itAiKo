python# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the working directory contents into the container at /app
COPY . /app

# Make port 8000 available to the world outside this container
EXPOSE 8000


# Run the command to start Gunicorn
CMD ["gunicorn", "myProject.wsgi:application", "--bind", "0.0.0.0:8000"]
