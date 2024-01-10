from flask import Flask, render_template
import pyodbc

app = Flask(__name__)

# Replace these with your MSSQL database credentials
db_config = {
    'server': 'localhost',
    'user': 'SA',
    'password': 'Passw0rd',
    'database': 'TestDB',
}

def get_data():
    # Connect to the MSSQL database
    connection = pyodbc.connect(
        'DRIVER={SQL Server};'
        f'SERVER={db_config["server"]};'
        f'DATABASE={db_config["database"]};'
        f'UID={db_config["user"]};'
        f'PWD={db_config["password"]};'
    )
    cursor = connection.cursor()

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    query = 'SELECT * FROM AppOrtamTable'
    cursor.execute(query)

    # Fetch column names
    columns = [column[0] for column in cursor.description]

    # Fetch all rows
    data = cursor.fetchall()

    # Close the connection
    connection.close()

    return columns, data

@app.route('/')
def index():
    columns, data = get_data()
    return render_template('index.html', columns=columns, data=data)

if __name__ == '__main__':
    app.run(debug=True)
