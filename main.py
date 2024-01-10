from flask import Flask, render_template, request
import pyodbc

app = Flask(__name__)

# Replace these with your MSSQL database credentials
db_config = {
    'server': 'localhost',
    'user': 'SA',
    'password': 'Passw0rd',
    'database': 'TestDB',
}

# Number of entries per page
entries_per_page = 10

def get_data(page,selected_columns):
    # Connect to the MSSQL database
    connection = pyodbc.connect(
        'DRIVER={SQL Server};'
        f'SERVER={db_config["server"]};'
        f'DATABASE={db_config["database"]};'
        f'UID={db_config["user"]};'
        f'PWD={db_config["password"]};'
    )
    cursor = connection.cursor()

    # Calculate the offset based on the current page
    offset = (page - 1) * entries_per_page
    
    # Execute a query to get the total number of rows
    count_query = 'SELECT COUNT(*) FROM AppOrtamTable'
    cursor.execute(count_query)
    total_rows = cursor.fetchone()[0]

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    query = f'SELECT * FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    cursor.execute(query)

    
    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # Only select the specified columns
    query = f'SELECT {", ".join(selected_columns)} FROM your_table ORDER BY your_column OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    cursor.execute(query)

    num_pages = (total_rows // entries_per_page) + (1 if total_rows % entries_per_page > 0 else 0)

    # Fetch column names
    columns = [column[0] for column in cursor.description]

    # Fetch all rows
    data = cursor.fetchall()

    # Close the connection
    connection.close()

    return columns, data, num_pages

@app.route('/')
def index():
    # Get the page number from the request's query parameters, default to 1 if not provided
    page = int(request.args.get('page', 1))
    
    columns, data, num_pages = get_data(page)
    
    return render_template('index.html', columns=columns, data=data, page=page, num_pages=num_pages)

if __name__ == '__main__':
    app.run(debug=True)
