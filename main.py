from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key' 
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=30)



# Replace these with your MSSQL database credentials
db_config = {
    'server': os.environ.get('DB_SERVER','localhost'),
    'user': os.environ.get('DB_USER','SA'),
    'password': os.environ.get('DB_PASSWORD','Passw0rd'),
    'database': os.environ.get('DB_DATABASE','TestDB'),
}

users = {
    'user1': 'password1',
    'user2': 'password2',
}

def is_valid_credentials(username, password):
    # Check if the provided username and password are valid
    return users.get(username) == password


# Number of entries per page
entries_per_page = 10

def get_db_connection():
    
    if(os.name=="nt"):
        driver="SQL Server"
        
    else:
        driver="ODBC Driver 17 for SQL Server"
    
    connection = pyodbc.connect(
            f'DRIVER={driver};'
            f'SERVER={db_config["server"]};'
            f'DATABASE={db_config["database"]};'
            f'UID={db_config["user"]};'
            f'PWD={db_config["password"]};'
        )
    
    return connection
    
def get_all_columns(table_name):
    # Connect to the MSSQL database
    connection = get_db_connection()
    cursor = connection.cursor()

    # Execute a query to get all column names for the specified table
    query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}'"
    cursor.execute(query)

    # Fetch all column names
    columns = [row.COLUMN_NAME for row in cursor.fetchall()]

    # Close the connection
    connection.close()

    return columns

def get_data(table_name):
 
    connection=get_db_connection()
    cursor = connection.cursor()

    # Calculate the offset based on the current page
    # offset = (page - 1) * entries_per_page
    
    # Execute a query to get the total number of rows
    count_query = 'SELECT COUNT(*) FROM AppOrtamTable'
    cursor.execute(count_query)
    # total_rows = cursor.fetchone()[0]

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # query = f'SELECT * FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # cursor.execute(query)
    
    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # Only select the specified columns
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH FIRST {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    query = f'SELECT * from {table_name}'

    cursor.execute(query)

    # num_pages = (total_rows // entries_per_page) + (1 if total_rows % entries_per_page > 0 else 0)

    # Fetch column names
    columns = [column[0] for column in cursor.description]

    # Fetch all rows
    data = cursor.fetchall()

    # Close the connection
    connection.close()

    return columns, data

@app.route('/')
def index():
    
    envanter_table_name="BackendEnvanter"
    # for key in request.form.keys():
    #     values = request.form.getlist(key)
    #     print("Key", key, "Value:", values)

    # # Get the selected columns from the submitted form data
    # selected_columns = request.args.getlist('selected_columns')

    # if not selected_columns:
    #     selected_columns = ['*']

    columns, data = get_data(envanter_table_name)
    
    selected_columns=["ServisTipi", "ServisAdı", "Makine", "ApplicationServerTipi", "JavaTipi", "UygulamaKritiklik", "UygulamaTipi"]
    detail_columns=["ostip", "JavaVersion", "dependecyJarTarama", "AAMEnabled", "ApplicationServerPath"]

    all_columns=get_all_columns(envanter_table_name)
    if 'username' in session:
        return render_template('index.html',username=session['username'], all_columns=all_columns, selected_columns=selected_columns, columns=columns, detail_columns=detail_columns, data=data)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_valid_credentials(username, password):
            session.permanent=True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'

    else:
        if 'username' in session:
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error=error) if 'error' in locals() else render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/test')
def deneme():
    return render_template('login.html')
if __name__ == '__main__':
    app.run(debug=True)
