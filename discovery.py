#!/usr/bin/env python3
"""
Middleware & Java Inventory Discovery Script
Discovers Java processes on Linux servers (root-less compatible)
Outputs JSON for FastAPI backend ingestion
"""

import subprocess
import re
import json
import os
import socket
from datetime import datetime

# Standard database ports to detect
DB_PORTS = ["1521", "5432", "50000", "1433", "3306", "27017", "6379", "9042"]


def run_command(cmd):
    """Execute system commands and return output."""
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""


def get_hostname():
    """Get the hostname of the current machine."""
    try:
        return socket.gethostname()
    except Exception:
        return run_command("hostname").strip() or "unknown"


def get_java_details(java_bin_path):
    """Get version and vendor information for a specific Java binary."""
    if not os.path.exists(java_bin_path):
        return {"path": java_bin_path, "vendor": "Unknown", "version": "Unknown"}
    
    version_output = run_command(f"{java_bin_path} -version 2>&1")
    
    vendor = "Oracle"
    if "openjdk" in version_output.lower():
        vendor = "OpenJDK"
    elif "ibm" in version_output.lower() or "j9" in version_output.lower():
        vendor = "IBM"
    elif "adoptium" in version_output.lower() or "temurin" in version_output.lower():
        vendor = "Eclipse Temurin"
        
    version_match = re.search(r'"(\d+\.\d+\.\S+)"', version_output)
    version = version_match.group(1) if version_match else "Unknown"
    
    return {
        "path": java_bin_path,
        "vendor": vendor,
        "version": version
    }


def get_db_connections(pid):
    """Get active database connections for a process (root-less compatible)."""
    connections = []
    lsof_cmd = f"lsof -i -nP -a -p {pid} 2>/dev/null"
    output = run_command(lsof_cmd)
    
    for line in output.split('\n'):
        if "ESTABLISHED" in line:
            # Extract IP:Port from lsof output
            # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            parts = line.split()
            if len(parts) >= 9:
                name_part = parts[-1]
                # Look for ->IP:PORT or IP:PORT-> patterns
                match = re.search(r'->(\d+\.\d+\.\d+\.\d+):(\d+)', name_part)
                if not match:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)->', name_part)
                if match:
                    ip, port = match.groups()
                    if port in DB_PORTS:
                        connections.append({
                            "host": ip,
                            "port": int(port),
                            "type": _identify_db_type(port)
                        })
    
    return connections


def _identify_db_type(port):
    """Identify database type based on port."""
    port_map = {
        "1521": "Oracle",
        "5432": "PostgreSQL",
        "50000": "DB2",
        "1433": "SQL Server",
        "3306": "MySQL",
        "27017": "MongoDB",
        "6379": "Redis",
        "9042": "Cassandra"
    }
    return port_map.get(port, "Unknown")


def extract_jvm_args(pid):
    """Extract JVM arguments from process command line."""
    try:
        # Read from /proc/PID/cmdline (root-less compatible)
        cmdline_path = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, 'r') as f:
                cmdline = f.read().replace('\0', ' ')
            return cmdline.strip()
    except Exception:
        pass
    
    # Fallback to ps command
    ps_output = run_command(f"ps -p {pid} -o args= 2>/dev/null")
    return ps_output


def identify_app_name(jvm_args):
    """Identify application name with priority:
    1. -Dinstance flag
    2. Middleware tags (-Dcatalina.base or --serverName)
    3. JAR name
    """
    app_name = None
    runtime_type = "Standalone"
    
    # Priority 1: -Dinstance flag
    instance_match = re.search(r'-Dinstance[=:](\S+)', jvm_args)
    if instance_match:
        app_name = instance_match.group(1)
    
    # Priority 2: Middleware tags
    if not app_name:
        # Tomcat: -Dcatalina.base
        catalina_match = re.search(r'-Dcatalina\.base[=:](\S+)', jvm_args)
        if catalina_match:
            catalina_path = catalina_match.group(1)
            # Extract server name from path (e.g., /opt/tomcat/myapp -> myapp)
            app_name = os.path.basename(catalina_path.rstrip('/'))
            runtime_type = "Tomcat"
        
        # Liberty: --serverName
        if not app_name:
            server_match = re.search(r'--serverName[=:](\S+)', jvm_args)
            if server_match:
                app_name = server_match.group(1)
                runtime_type = "Liberty"
        
        # WebSphere: -DserverName or -Dwas.install.root
        if not app_name:
            was_match = re.search(r'-DserverName[=:](\S+)', jvm_args)
            if was_match:
                app_name = was_match.group(1)
                runtime_type = "WebSphere"
    
    # Priority 3: JAR name
    if not app_name:
        jar_match = re.search(r'([^/\s]+\.jar)', jvm_args)
        if jar_match:
            jar_name = jar_match.group(1)
            app_name = os.path.splitext(jar_name)[0]
    
    # Fallback: use main class or first argument
    if not app_name:
        # Try to extract main class
        main_class_match = re.search(r'\s([a-zA-Z][a-zA-Z0-9_.]*\.Main)\s', jvm_args)
        if main_class_match:
            app_name = main_class_match.group(1).split('.')[-1]
        else:
            # Last resort: use first non-flag argument
            parts = jvm_args.split()
            for part in parts:
                if not part.startswith('-') and not part.startswith('/'):
                    app_name = os.path.basename(part)
                    break
    
    return app_name or "unknown", runtime_type


def get_java_binary_path(jvm_args):
    """Extract Java binary path from JVM arguments or process."""
    # Look for java executable in the command
    java_match = re.search(r'(\S*java\S*)\s', jvm_args)
    if java_match:
        java_path = java_match.group(1)
        if os.path.exists(java_path):
            return java_path
    
    # Try common Java paths
    common_paths = [
        "/usr/bin/java",
        "/usr/local/bin/java",
        "/opt/java/bin/java",
        "/usr/lib/jvm/default/bin/java"
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None


def discover_java_processes():
    """Discover all Java processes on the system."""
    processes = []
    
    # Find all Java processes (root-less compatible)
    # Use ps to find Java processes
    ps_output = run_command("ps -eo pid,comm,args | grep -i java | grep -v grep")
    
    if not ps_output:
        return processes
    
    seen_pids = set()
    
    for line in ps_output.split('\n'):
        if not line.strip():
            continue
        
        # Parse ps output: PID COMMAND ARGS
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        
        try:
            pid = int(parts[0])
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            
            # Get full command line
            jvm_args = extract_jvm_args(pid)
            if not jvm_args or 'java' not in jvm_args.lower():
                continue
            
            # Identify app name and runtime
            app_name, runtime_type = identify_app_name(jvm_args)
            
            # Get Java binary path
            java_bin_path = get_java_binary_path(jvm_args)
            if not java_bin_path:
                # Try to get from /proc/PID/exe symlink
                try:
                    exe_path = os.readlink(f"/proc/{pid}/exe")
                    if os.path.exists(exe_path):
                        java_bin_path = exe_path
                    else:
                        # Try to resolve relative path
                        exe_dir = os.path.dirname(f"/proc/{pid}/exe")
                        resolved = os.path.join(exe_dir, exe_path)
                        if os.path.exists(resolved):
                            java_bin_path = resolved
                        else:
                            java_bin_path = "unknown"
                except (OSError, FileNotFoundError):
                    java_bin_path = "unknown"
            
            # Get Java details
            java_info = get_java_details(java_bin_path) if java_bin_path != "unknown" else {
                "path": "unknown",
                "vendor": "Unknown",
                "version": "Unknown"
            }
            
            # Extract JVM arguments as a list
            jvm_args_list = []
            arg_matches = re.finditer(r'(-[DX]\S+)(?:[=:](\S+))?', jvm_args)
            for match in arg_matches:
                arg = match.group(1)
                value = match.group(2) if match.group(2) else None
                if value:
                    jvm_args_list.append(f"{arg}={value}")
                else:
                    jvm_args_list.append(arg)
            
            # Get database connections
            db_connections = get_db_connections(pid)
            
            # Get working directory
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd") if os.path.exists(f"/proc/{pid}/cwd") else None
            except Exception:
                cwd = None
            
            process_data = {
                "pid": pid,
                "hostname": get_hostname(),
                "app_name": app_name,
                "runtime_type": runtime_type,
                "java": java_info,
                "jvm_args": jvm_args_list,
                "jvm_args_raw": jvm_args,
                "db_connections": db_connections,
                "working_directory": cwd,
                "discovered_at": datetime.utcnow().isoformat() + "Z"
            }
            
            processes.append(process_data)
            
        except (ValueError, IndexError) as e:
            continue
    
    return processes


def main():
    """Main entry point for discovery script."""
    try:
        processes = discover_java_processes()
        
        # Output JSON for API consumption
        output = {
            "hostname": get_hostname(),
            "discovered_at": datetime.utcnow().isoformat() + "Z",
            "processes": processes,
            "process_count": len(processes)
        }
        
        print(json.dumps(output, indent=2))
        return 0
        
    except Exception as e:
        error_output = {
            "error": str(e),
            "hostname": get_hostname(),
            "discovered_at": datetime.utcnow().isoformat() + "Z",
            "processes": []
        }
        print(json.dumps(error_output, indent=2))
        return 1


if __name__ == "__main__":
    exit(main())
