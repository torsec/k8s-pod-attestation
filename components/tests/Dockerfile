# custom image for attestation
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the application files to the working directory
COPY . .

# Install any necessary packages (example: bash)
RUN apk add --no-cache bash

# Set the default command to run your application (adjust based on your application)
CMD ["bash"]
