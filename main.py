from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import os
import pytz

from config import users, user_roles, LDAP_ENABLED
from parse_fw import parse_fw_file
from sharepoint_manager import download_latest_sharepoint_files, should_download_files, merge_fw_files, schedule_daily_download
from auth import is_valid_credentials, authenticate_ldap_user, get_user_allowed_endpoints
from database import get_data, get_all_columns, update_os_version, insert_query, get_runtime_stats

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.route('/')
def index():
    if 'username' in session:
        if '/' not in get_user_allowed_endpoints(session['username']):
            return redirect(url_for('firewall'))

        envanter_table_name = "BackendEnvanter"
        columns, data = get_data(envanter_table_name)

        selected_columns = ["ServisTipi", "ServisAdı", "Makine",
                            "ApplicationServerTipi", "JavaTipi", "UygulamaKritiklik", "UygulamaTipi"]
        detail_columns = ["ostip", "JavaVersion", "AAMEnabled", "ApplicationServerPath"]

        all_columns = get_all_columns(envanter_table_name)
        return render_template(
            'index.html', username=session['username'],
            all_columns=all_columns, selected_columns=selected_columns, columns=columns, detail_columns=detail_columns,
            data=data, allowed_endpoints=get_user_allowed_endpoints(session['username']))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not LDAP_ENABLED and is_valid_credentials(username, password):
            session.permanent = True
            session['username'] = username
            return redirect(url_for('index'))
        elif LDAP_ENABLED and authenticate_ldap_user(username, password):
            session.permanent = True
            session['username'] = username
            if username not in users:
                users[username] = 'default'
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
            return render_template('login.html', error=error) if 'error' in locals() else render_template('login.html')

    else:
        if 'username' in session:
            return redirect(url_for('index'))
        else:
            return render_template('login.html') if 'error' in locals() else render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/chart')
def chart():
    if 'username' in session:
        if '/chart' not in get_user_allowed_endpoints(session['username']):
            return redirect(url_for('fw'))

        runtime_stats = get_runtime_stats()
        return render_template('chart.html', runtime_stats=runtime_stats,
                               allowed_endpoints=get_user_allowed_endpoints(session['username']))
    else:
        return redirect(url_for('login'))

@app.route('/fw')
def firewall():
    if 'username' in session:
        if '/fw' not in get_user_allowed_endpoints(session['username']):
            return redirect(url_for('index'))

        file_path = os.path.join('static', 'merged_fw.txt')
        last_updated = None

        if should_download_files():
            print("Downloading new files...")
            downloaded_files = download_latest_sharepoint_files()

            if downloaded_files:
                merged_content = merge_fw_files(downloaded_files.values())
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(merged_content)
                last_updated = datetime.now(pytz.timezone('Europe/Istanbul'))
            else:
                file_path = 'static/samplefw.txt'
        else:
            print("Using existing merged file...")
            if os.path.exists(file_path):
                last_updated = datetime.fromtimestamp(os.path.getmtime(file_path), pytz.timezone('Europe/Istanbul'))

        groups = parse_fw_file(file_path)
        groups_dict = {g['name']: g for g in groups}

        child_groups = {child for group in groups for child in group['children']}
        filtered_groups = [group for group in groups if group['name'] not in child_groups]

        return render_template('fw.html',
                               groups=filtered_groups,
                               groups_dict=groups_dict,
                               last_updated=last_updated.strftime('%Y-%m-%d %H:%M:%S') if last_updated else None,
                               allowed_endpoints=get_user_allowed_endpoints(session['username']),
                               username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/trigger-download', methods=['POST'])
def trigger_download():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

    try:
        downloaded_files = download_latest_sharepoint_files()

        if downloaded_files:
            merged_file_path = os.path.join('static', 'merged_fw.txt')
            merged_content = merge_fw_files(downloaded_files.values())
            with open(merged_file_path, 'w', encoding='utf-8') as f:
                f.write(merged_content)

            return jsonify({
                'status': 'success',
                'message': f'Successfully downloaded and merged {len(downloaded_files)} files',
                'files': list(downloaded_files.keys()),
                'last_updated': datetime.now(pytz.timezone('Europe/Istanbul')).strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({
                'status': 'warning',
                'message': 'No files were downloaded'
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error during download: {str(e)}'
        }), 500

@app.route('/add_service', methods=['POST'])
def add_service():
    if request.method == 'POST':
        hostname = request.json['hostname']
        servicenames = request.json['servicenames']
        insert_query(hostname, servicenames)
        return "Succesfully added entry"

@app.route('/update_os_version', methods=['POST'])
def update_os_handler():
    if request.method == 'POST':
        hostname = request.json['hostname']
        os_version = request.json['os_version']
        update_os_version(hostname, os_version)
        return "Succesfully added entry"

if __name__ == '__main__':
    # Start the scheduler in a separate thread
    import threading
    scheduler_thread = threading.Thread(target=schedule_daily_download, daemon=True)
    scheduler_thread.start()

    # Run Flask without debug mode for Docker
    app.run(host='0.0.0.0', debug=False)
