import mysql.connector

# Step 1: Connect to the MySQL database
conn = mysql.connector.connect(
    host="localhost",      # Database host (use 127.0.0.1 if localhost fails)
    user="ben",            # Your MySQL username
    password="12345678$", # Your MySQL password
    database="fyp"         # Name of the database to connect to
)
cursor = conn.cursor()

print("Connected to MySQL successfully.")

# Step 2: Create the 'users' table if it does not already exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE
)
""")
print("Table 'users' is ready.")


# Step 3: Insert a user only if the table is currently empty
cursor.execute("SELECT COUNT(*) FROM users")
count = cursor.fetchone()[0]
if count == 0:
    cursor.execute(
        "INSERT INTO users (name, email) VALUES (%s, %s)",
        ("Ben Murphy", "benmurphy565@gmail.com")
    )
    conn.commit()
    print("User inserted into database.")

# Step 4: Read all rows from the 'users' table and print them
cursor.execute("SELECT * FROM users")
records = cursor.fetchall()

print("Users in database:")
for row in records:
    print(row)

# Step 5: Close the cursor and database connection
cursor.close()
conn.close()
