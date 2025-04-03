import csv

from app import get_db_connection

def migrate_csv():
    try:
        conn = get_db_connection()  # Connect to the database
        cur = conn.cursor()

        # Ensure table exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS products(
                id SERIAL PRIMARY KEY,
                name VARCHAR(255),
                price FLOAT
            )
        """)
        conn.commit()

        with open('static/data/products.csv', 'r') as f:
            reader = csv.reader(f)
            print("Migrating CSV data...")
            print("Please wait...")
            next(reader)  # Skip header

            # Insert data into the database
            for row in reader:
                cur.execute(
                    "INSERT INTO products (name, price) VALUES (%s, %s);", (row[1], row[2]))

        conn.commit()
        cur.close()
        conn.close()

        print("CSV data migrated successfully")
        return "CSV data migrated successfully"

    except Exception as e:
        return f"An error occurred while migrating the CSV: {str(e)}", 500

if __name__ == "__main__":
    migrate_csv()