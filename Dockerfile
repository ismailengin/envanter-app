# Use an official Python runtime as a parent image
FROM docker.io/laudio/pyodbc

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variables
ENV FLASK_APP=main.py
ENV PYTHONUNBUFFERED=1

RUN chmod -R 777 /app/static

# Run app.py when the container launches
CMD ["python", "main.py"]

