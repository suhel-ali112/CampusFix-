import os
import mysql.connector
from dotenv import load_dotenv

# .env file se credentials load karein
load_dotenv()

def setup_database():
    try:
        # Aiven database se connection establish karein
        connection = mysql.connector.connect(
            host=os.environ.get('DB_HOST'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASSWORD'),
            database=os.environ.get('DB_NAME'),
            port=int(os.environ.get('DB_PORT', 3306))
        )
        
        cursor = connection.cursor()
        print(" Connected to Aiven Database successfully!")

        # schema.sql file ko read karein
        schema_path = os.path.join('database', 'schema.sql')
        with open(schema_path, 'r') as f:
            sql_script = f.read()

        # Statements ko ';' se split karke ek-ek karke execute karein
        statements = sql_script.split(';')
        for statement in statements:
            if statement.strip():
                cursor.execute(statement)

        connection.commit()
        print(" Tables created successfully in Aiven Cloud Database!")

    except Exception as e:
        print(f" Error aa gaya: {e}")

    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print(" Database connection closed.")

if __name__ == '__main__':
    setup_database()