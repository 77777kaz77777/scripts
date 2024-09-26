#!/bin/bash

# Function to create a new user
create_user() {
  local USERNAME=$1
  local PASSWORD=$2

  # Check if the username is already taken
  if id -u "$USERNAME" &>/dev/null; then
    echo "Username already taken. Please choose a different username."
    return 1
  fi

  # Create the new user
  if ! sudo useradd -m -s /bin/bash "$USERNAME"; then
    echo "Failed to create user $USERNAME."
    return 1
  fi

  # Hash the password using mkpasswd
  local HASHED_PASSWORD=$(mkpasswd -m sha-512 "$PASSWORD")

  # Set the password
  if ! echo "$USERNAME:$HASHED_PASSWORD" | sudo chpasswd -e; then
    echo "Failed to set password for user $USERNAME."
    return 1
  fi

  # Add the user to the sudo group (optional)
  if ! sudo usermod -aG sudo "$USERNAME"; then
    echo "Failed to add user $USERNAME to sudo group."
    return 1
  fi

  # Update the /etc/skel/.bashrc file to set the default shell prompt
  if ! sudo tee -a /etc/skel/.bashrc <<EOF
PS1='\[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
EOF
  then
    echo "Failed to update /etc/skel/.bashrc file."
    return 1
  fi
}

# Function to validate input
validate_input() {
  local USERNAME=$1
  local PASSWORD=$2

  # Check if the username is valid
  if [[ ! $USERNAME =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Invalid username. Please use only letters, numbers, and underscores."
    return 1
  fi

  # Check if the password is strong enough
  if [[ ${#PASSWORD} -lt 8 ]]; then
    echo "Password is too short. Please use a password with at least 8 characters."
    return 1
  fi
}

# Function to handle errors
handle_error() {
  local MESSAGE=$1
  echo "Error: $MESSAGE"
  exit 1
}

# Main script
if [ $# -ne 1 ]; then
  echo "Usage: $0 <csv_file>"
  exit 1
fi

CSV_FILE=$1

if [ ! -f "$CSV_FILE" ]; then
  handle_error "CSV file not found"
fi

while IFS=, read -r USERNAME PASSWORD; do
  # Validate input
  if ! validate_input "$USERNAME" "$PASSWORD"; then
    handle_error "Invalid input. Please try again."
  fi

  # Create the new user
  if ! create_user "$USERNAME" "$PASSWORD"; then
    handle_error "Failed to create user $USERNAME."
  fi

  echo "User $USERNAME created successfully."
done < "$CSV_FILE"
