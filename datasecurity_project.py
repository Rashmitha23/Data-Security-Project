import mysql.connector
import hashlib
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import random

# Database connection
def get_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",  # Replace with your MySQL username
            password="Rashmitha@23",  # Replace with your MySQL password
            database="healthcare_db"
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Encryption and decryption utilities for sensitive data
def encrypt_data(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def decrypt_data(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Generate a random encryption key
ENCRYPTION_KEY = b'static_key_16byt'  # Use a consistent 16-byte key

# Create tables and seed data
def create_tables_and_seed():
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE,
                    password_hash VARCHAR(255),
                    group_type ENUM('H', 'R')
                );
            """)
            # Create healthcare data table with restricted health_history values
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS healthcare_data (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    gender TEXT,
                    age TEXT,
                    weight FLOAT,
                    height FLOAT,
                    health_history ENUM('No significant issues', 'Cold', 'Cancer', 'Diabetes'),
                    record_hash VARCHAR(64)
                );
            """)
            connection.commit()

            # Seed 100 random healthcare records if table is empty
            cursor.execute("SELECT COUNT(*) FROM healthcare_data;")
            if cursor.fetchone()[0] == 0:
                for _ in range(100):
                    first_name = f"User{random.randint(1, 1000)}"
                    last_name = f"Test{random.randint(1, 1000)}"
                    gender = encrypt_data(ENCRYPTION_KEY, str(random.choice(['Female', 'Male'])))
                    age = encrypt_data(ENCRYPTION_KEY, str(random.randint(18, 80)))
                    weight = round(random.uniform(50.0, 100.0), 1)
                    height = round(random.uniform(1.5, 2.0), 2)
                    health_history = str(random.choice(['No significant issues', 'Cold', 'Cancer', 'Diabetes']))
                    record_hash = hashlib.sha256(f"{first_name}{last_name}{gender}{age}".encode()).hexdigest()
                    cursor.execute("""
                        INSERT INTO healthcare_data (first_name, last_name, gender, age, weight, height, health_history, record_hash)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """, (first_name, last_name, gender, age, weight, height, health_history, record_hash))
                connection.commit()
                print("Seeded 100 healthcare records.")
        except Exception as e:
            print(f"Error creating tables or seeding data: {e}")
        finally:
            cursor.close()
            connection.close()

# Register user
def register_user(username, password, group_type):
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = %s;", (username,))
            if cursor.fetchone():
                print(f"Username '{username}' already exists. Please choose a different username.")
                return

            # Insert new user
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            cursor.execute("""
                INSERT INTO users (username, password_hash, group_type)
                VALUES (%s, %s, %s);
            """, (username, password_hash.decode(), group_type))
            connection.commit()
            print(f"User '{username}' registered successfully.")
        except Exception as e:
            print(f"Error registering user: {e}")
        finally:
            cursor.close()
            connection.close()

# Authenticate user
def authenticate_user(username, password):
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT password_hash, group_type FROM users WHERE username = %s;", (username,))
            result = cursor.fetchone()
            if result and bcrypt.checkpw(password.encode(), result[0].encode()):
                return result[1]
        except Exception as e:
            print(f"Error during authentication: {e}")
        finally:
            cursor.close()
            connection.close()
    return None

# Add healthcare data
def add_healthcare_data(user_group, data):
    if user_group != 'H':
        print("Permission denied! Only Group H can add data.")
        return
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor()
            encrypted_gender = encrypt_data(ENCRYPTION_KEY, str(data['gender']))
            encrypted_age = encrypt_data(ENCRYPTION_KEY, str(data['age']))
            data_hash = hashlib.sha256(f"{data['first_name']}{data['last_name']}{data['gender']}{data['age']}".encode()).hexdigest()
            cursor.execute("""
                INSERT INTO healthcare_data (first_name, last_name, gender, age, weight, height, health_history, record_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """, (data['first_name'], data['last_name'], encrypted_gender, encrypted_age, data['weight'], data['height'], data['health_history'], data_hash))
            connection.commit()
        except Exception as e:
            print(f"Error adding healthcare data: {e}")
        finally:
            cursor.close()
            connection.close()

# Query healthcare data with integrity checks
def query_healthcare_data(user_group):
    connection = get_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)

            # Fetch data based on user group
            if user_group == 'H':
                cursor.execute("SELECT * FROM healthcare_data;")
            elif user_group == 'R':
                cursor.execute("SELECT id, gender, age, weight, height, health_history, record_hash FROM healthcare_data;")
            
            results = cursor.fetchall()
            
            if not results:
                print("No data available to display.")
                return
            
            # Initialize cumulative hash for completeness
            cumulative_hash = hashlib.sha256()
            record_ids = set()  # Track record IDs for completeness checks
            
            for row in results:
                # Decrypt sensitive fields for Group R
                if user_group == 'R':
                    try:
                        row['gender'] = decrypt_data(ENCRYPTION_KEY, row['gender'])
                        row['age'] = decrypt_data(ENCRYPTION_KEY, row['age'])
                    except Exception as e:
                        print(f"Error decrypting data for record {row['id']}: {e}")
                        row['gender'] = "Error"
                        row['age'] = "Error"

                    # Restrict access to first_name and last_name for Group R
                    row['first_name'] = "Restricted"
                    row['last_name'] = "Restricted"
                
                # Validate record integrity using record_hash
                record_data = f"{row['first_name']}{row['last_name']}{row['gender']}{row['age']}".encode()
                computed_hash = hashlib.sha256(record_data).hexdigest()
                if computed_hash != row['record_hash']:
                    print(f"Integrity issue detected for record ID {row['id']}: Data may be tampered.")
                
                # Add record hash to cumulative hash for completeness check
                cumulative_hash.update(row['record_hash'].encode())
                record_ids.add(row['id'])  # Track record IDs
                
                # Display the record
                print(row)

            
            expected_cumulative_hash = hashlib.sha256("".join(sorted(record_ids)).encode()).hexdigest()

            # Verify query completeness
            if cumulative_hash.hexdigest() != expected_cumulative_hash:
                print("Query completeness issue: Some records may be missing.")
        
        except Exception as e:
            print(f"Error querying healthcare data: {e}")
        finally:
            cursor.close()
            connection.close()


# Main program
if _name_ == "_main_":
    create_tables_and_seed()
    register_user("group_H", "securepassword", "H")
    register_user("group_R", "guestpassword", "R")

    username = input("Enter your username: ")
    password = input("Enter your password: ")
    user_group = authenticate_user(username, password)

    if user_group:
        print(f"Authenticated as {username}, Group: {user_group}")
        if user_group=='H':
            add_data = input('Do you want to add new data into the table? ["Yes/No"]: ')

            if add_data.lower() == "yes":
                if user_group == "H":
                    print("Please enter the healthcare data to be added:")
                    first_name = input("First Name: ")
                    last_name = input("Last Name: ")
                    gender = input("Gender (Male/Female): ")
                    age = int(input("Age: "))
                    weight = float(input("Weight: "))
                    height = float(input("Height: "))
                    health_history = input("Health History (No significant issues, Cold, Cancer, Diabetes): ")

                    add_healthcare_data(user_group, {
                        "first_name": first_name,
                        "last_name": last_name,
                        "gender": gender,
                        "age": age,
                        "weight": weight,
                        "height": height,
                        "health_history": health_history
                    })
                else:
                    print("Permission denied! Only Group H can add data.")
        query_healthcare_data(user_group)
    else:
        print("Authentication failed.")