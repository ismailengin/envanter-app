import os
import requests
from requests_ntlm import HttpNtlmAuth
import json
import schedule
import time
from datetime import datetime
import urllib3
import pytz
from config import (
    SHAREPOINT_SITE_URL, SHAREPOINT_USERNAME, SHAREPOINT_PASSWORD, SHAREPOINT_DOMAIN,
    SHAREPOINT_ROOT_FOLDER
)
from parse_fw import parse_fw_file

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def discover_sharepoint_folders():
    """Discover all folders in the SharePoint site"""
    try:
        site_url = SHAREPOINT_SITE_URL
        username = SHAREPOINT_USERNAME
        password = SHAREPOINT_PASSWORD
        domain = SHAREPOINT_DOMAIN
        root_folder = SHAREPOINT_ROOT_FOLDER

        auth = HttpNtlmAuth(f"{domain}\\{username}", password)

        headers = {
            'Accept': 'application/json;odata=verbose',
            'Content-Type': 'application/json;odata=verbose'
        }

        api_base = f"{site_url}/_api/web"
        root_folder_url = f"{api_base}/GetFolderByServerRelativeUrl('{root_folder}')/Folders"

        response = requests.get(root_folder_url, auth=auth, headers=headers, verify=False)
        response.raise_for_status()

        folders = []
        root_folders = response.json()['d']['results']

        for folder in root_folders:
            folder_url = folder['ServerRelativeUrl']
            folders.append(folder_url)

            try:
                subfolders_url = f"{api_base}/GetFolderByServerRelativeUrl('{folder_url}')/Folders"
                subfolders_response = requests.get(subfolders_url, auth=auth, headers=headers, verify=False)
                subfolders_response.raise_for_status()

                subfolders = subfolders_response.json()['d']['results']
                for subfolder in subfolders:
                    folders.append(subfolder['ServerRelativeUrl'])
            except Exception as e:
                print(f"Error getting subfolders for {folder_url}: {str(e)}")
                continue

        return folders

    except Exception as e:
        print(f"Error discovering folders: {str(e)}")
        return []

def download_latest_sharepoint_files():
    """Download the latest file from each discovered SharePoint folder using NTLM authentication"""
    print(f"Starting download at {datetime.now(pytz.timezone('Europe/Istanbul')).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    try:
        site_url = SHAREPOINT_SITE_URL
        username = SHAREPOINT_USERNAME
        password = SHAREPOINT_PASSWORD
        domain = SHAREPOINT_DOMAIN
        root_folder = SHAREPOINT_ROOT_FOLDER

        folder_urls = discover_sharepoint_folders()
        if not folder_urls:
            print("No folders discovered")
            return {}

        auth = HttpNtlmAuth(f"{domain}\\{username}", password)

        headers = {
            'Accept': 'application/json;odata=verbose',
            'Content-Type': 'application/json;odata=verbose'
        }

        downloaded_files = {} # Dictionary to store downloaded files by folder

        for folder_url in folder_urls:
            try:
                api_base = f"{site_url}/_api/web"
                folder_api_url = f"{api_base}/GetFolderByServerRelativeUrl('{folder_url}')/Files"

                response = requests.get(folder_api_url, auth=auth, headers=headers, verify=False)
                response.raise_for_status()

                files_data = response.json()['d']['results']

                if not files_data:
                    print(f"No files found in folder: {folder_url}")
                    continue

                filtered_files = [
                    f for f in files_data
                    if f['Name'].lower().endswith('.txt') and '2025' in f['Name']
                ]

                if not filtered_files:
                    print(f"No matching files found in folder: {folder_url}")
                    continue

                latest_file = max(filtered_files, key=lambda x: datetime.strptime(
                    x['TimeLastModified'], "%Y-%m-%dT%H:%M:%SZ"))

                file_url = latest_file['ServerRelativeUrl'].split('/')
                file_actual_url = '/' + '/'.join(file_url[(len(root_folder.split('/')) -1):])
                file_name = os.path.basename(file_actual_url)
                download_path = os.path.join('static', file_name)

                file_response = requests.get(f"{site_url}{file_actual_url}", auth=auth, verify=False)
                file_response.raise_for_status()

                with open(download_path, "wb") as local_file:
                    local_file.write(file_response.content)

                print(f"Successfully downloaded {file_name} from {folder_url}")
                downloaded_files[folder_url] = download_path

            except requests.exceptions.RequestException as e:
                print(f"Error processing folder {folder_url}: {str(e)}")
                continue
            except Exception as e:
                print(f"Unexpected error processing folder {folder_url}: {str(e)}")
                continue

        return downloaded_files

    except Exception as e:
        print(f"Unexpected error in main process: {str(e)}")
        return {}

def schedule_daily_download():
    """Schedule the daily download at 7:00 AM Istanbul time"""
    def job():
        istanbul_tz = pytz.timezone('Europe/Istanbul')
        ist_time = datetime.now(istanbul_tz)
        print(f"Current time in Istanbul: {ist_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        downloaded_files = download_latest_sharepoint_files()
        if downloaded_files:
            try:
                merged_file_path = os.path.join('static', 'merged_fw.txt')
                merged_content = merge_fw_files(downloaded_files.values())
                with open(merged_file_path, 'w', encoding='utf-8') as f:
                    f.write(merged_content)
                print(f"Scheduled job: merged {len(downloaded_files)} files into {merged_file_path}")
            except Exception as e:
                print(f"Scheduled job: failed to merge downloaded files: {e}")

    schedule.every().day.at("04:00").do(job)
    print("Scheduled daily download for 7:00 AM Istanbul time...")
    
    while True:
        schedule.run_pending()
        time.sleep(60)

def merge_fw_files(file_paths):
    """Merge multiple firewall files into a single file with proper separators"""
    merged_content = []

    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read().strip()
                if content: # Only add non-empty content
                    merged_content.append(content)
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            continue

    return '\n==============================\n'.join(merged_content)

def should_download_files():
    """Check if files should be downloaded based on file existence and age"""
    merged_file_path = os.path.join('static', 'merged_fw.txt')

    if not os.path.exists(merged_file_path):
        return True

    file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(merged_file_path))

    return file_age.total_seconds() > 24 * 3600
