import logging.config
import os
import base64
from typing import List
from dotenv import load_dotenv
from jose import jwt
from datetime import datetime, timedelta
from app.config import ADMIN_PASSWORD, ADMIN_USER, ALGORITHM, SECRET_KEY
import validators  # Make sure to install this package
from urllib.parse import urlparse, urlunparse

# Load environment variables from .env file for security and configuration.
load_dotenv()

def initialize_logging():
    """
    Sets up logging for the application using a Config file.
    This ensures one point access to all standardized logging across the entire application.
    """
    # Construct the path to 'logging.conf', assuming it's in the project's root.
    logging_config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logging.conf')
    # Normalize the path to handle any '..' correctly.
    normalized_path = os.path.normpath(logging_config_path)
    # Apply the logging configuration.
    logging.config.fileConfig(normalized_path, disable_existing_loggers=False)

def authenticate_user(username: str, password: str):
    """
    One point for user authentication logic.
    In a real application, replace this with actual authentication against a user database.
    """
    
    # Simple check against constants for demonstration.
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        logging.info(f"User authenticated successfully : {username}")
        return {"username": username}
    # Log a warning if authentication fails.
    logging.warning(f"Authentication failed for user: {username}")
    return None

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Generates a JWT user access token. Optionally, an expiration time can be specified.
    """
    # Copy user data and set expiration time for the token.
    logging.info(f"Creating JWT Token.")
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    # Encode the data to create the JWT.
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def validate_and_sanitize_url(url_str):
    """
    Validates a given URL string and returns a sanitized version if valid.
    Returns None if the URL is invalid;
    This is used to ensure that only safe and valid URLs are processed.
    """
    logging.info(f"Sanitizing teh given URL : {url_str}")
    if validators.url(url_str):
        parsed_url = urlparse(url_str)
        sanitized_url = urlunparse(parsed_url)
        return sanitized_url
    else:
        logging.error(f"The URL provided is invalid : {url_str}")
        return None

def encode_url_to_filename(url):
    """
    Encodes the given URL into a base64 string to ensure safety for filenames, after validating and sanitizing it.
    Removes padding to ensure filename compatibility.
    """
    logging.info(f"Encoding the given URL : {url}")
    sanitized_url = validate_and_sanitize_url(str(url))
    if sanitized_url is None:
        raise ValueError("Provided URL is invalid and cannot be encoded.")
    encoded_bytes = base64.urlsafe_b64encode(sanitized_url.encode('utf-8'))
    encoded_str = encoded_bytes.decode('utf-8').rstrip('=')
    return encoded_str

def decode_filename_to_url(encoded_str: str) -> str:
    """
    This function decodes a base64 encoded string back into a URL,and adding any necessary padding.
    This reverses the process done by `encode_url_to_filename` function.
    """
    logging.info(f"Decoding the given encoded URL String")
    padding_needed = 4 - (len(encoded_str) % 4)
    if padding_needed:
        encoded_str += "=" * padding_needed
    decoded_bytes = base64.urlsafe_b64decode(encoded_str)
    return decoded_bytes.decode('utf-8')

def generate_links(action: str, qr_filename: str, base_api_url: str, download_url: str) -> List[dict]:
    """
    Generates HATEOAS links for QR code resources, including view and delete actions.
    This supports the application's RESTful architecture by providing links to possible actions.
    """
    logging.info(f"Generating the HATEOAS links for QR Code resources.")
    links = []
    if action in ["list", "create"]:
        original_url = decode_filename_to_url(qr_filename[:-4])
        links.append({"rel": "view", "href": download_url, "action": "GET", "type": "image/png"})
    if action in ["list", "create", "delete"]:
        delete_url = f"{base_api_url}/qr-codes/{qr_filename}"
        links.append({"rel": "delete", "href": delete_url, "action": "DELETE", "type": "application/json"})
    return links
