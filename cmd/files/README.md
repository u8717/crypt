# hold engine

hold engine is a simple and secure key-value store designed for data integrity and encryption.

This Project is currently WiP.

## Features

- **Data Integrity:** Ensures the consistency and authenticity of stored or logged data through integrity tokens.
- **Encryption:** Provides optional encryption for sensitive information using encryption tokens.
- **Timestamps:** Records and tracks timestamps for every key-value entry.
- **Signature Verification:** Verifies data integrity using HMAC-based signature verification.
- **Namespace Support:** Allows grouping keys under different namespaces for better organization.
- **Sorting:** Supports sorting of keys based on specified criteria (e.g., name, timestamp, value).
- **Pagination:** Enables pagination for efficient handling of large key sets.
- **Import State from Logs:** Restoration of hold's state by importing data from system logs.

## Getting Started

1. Install holdDB engine by [downloading the latest release](#) or building from source.
2. Set up your configuration, including integrity and encryption tokens.
3. Use the provided CLI commands for creating, updating, deleting, merging, and listing keys.

## Usage

```bash
# Create a new item
holdDB create <key> <value>

# Delete an item
holdDB delete <key>

# Update an item
holdDB update <key> <value>

# Merge an item
holdDB merge <key> <entry>

# Get an item
holdDB get <key>

# List all registered keys per namespace
holdDB list

## Configuration

- **Integrity Token:** Set the `--integrityToken` flag to provide the integrity token for data signing and verification.
- **Encryption Token:** Set the `--encryptionToken` flag to enable encryption and provide the encryption token.
- **Namespace:** Use the `--namespace` flag to specify the namespace for grouping keys.
