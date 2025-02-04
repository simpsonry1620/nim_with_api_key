import sqlite3
import logging

DATABASE_FILE = "app.db"

def init_db():
    conn = get_db_connection()
    if conn is not None:
        try:
            with open('./app/schema.sql', 'r') as f:
                conn.cursor().executescript(f.read())
            conn.commit()
            logging.debug("DEBUG: Database initialized successfully.") 
            print("Database initialized successfully.")
        except sqlite3.Error as e:
            print(f"Error initializing database: {e}")
            logging.error(f"DEBUG: Error initializing database: {e}")
        finally:
            logging.debug("DEBUG: Closing connection to database.")
            conn.close()
    else:
        logging.error("DEBUG: Failed to initialize database: could not get a database connection.")
        print("Failed to initialize database: could not get a database connection.")

def get_db_connection():
    conn = None
    try:
        logging.debug("DEBUG: Connecting to database")
        conn = sqlite3.connect(DATABASE_FILE)
        conn.execute('PRAGMA foreign_keys = ON')  # Enable foreign key support
        logging.debug("DEBUG: Connected to database")
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        logging.error(f"DEBUG: Error connecting to database: {e}")
    return conn

