# parse_fw.py
import re
from collections import defaultdict
import socket
import os
import dns.resolver # Import dnspython

DEBUG_DNS_RESOLUTION = os.environ.get('DEBUG_DNS_RESOLUTION', 'false').lower() == 'true'


def extract_ip_from_string(text):
    # Regex to find an IPv4 address
    ip_pattern = r'(?<!\d)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d)'
    match = re.search(ip_pattern, text)
    if match:
        return match.group(0)
    return None


def resolve_ip(ip_address):
    resolved_hostnames = []
    try:
        # Try to get hostnames using dnspython for multiple PTR records
        try:
            # Removed explicit lifetime parameter; dnspython will use its default or system configured timeout.
            rev_name = dns.reversename.from_address(ip_address)
            ptr_records = dns.resolver.resolve(rev_name, "PTR")
            for ptr in ptr_records:
                hostname = str(ptr.target).rstrip('.')
                resolved_hostnames.append(hostname)
                if DEBUG_DNS_RESOLUTION:
                    print(f"DEBUG DNS: Resolved IP {ip_address} to hostname {hostname} via PTR")
        except dns.resolver.NXDOMAIN:
            if DEBUG_DNS_RESOLUTION:
                print(f"DEBUG DNS: No PTR record for {ip_address}")
        except dns.resolver.NoAnswer:
            if DEBUG_DNS_RESOLUTION:
                print(f"DEBUG DNS: No answer for PTR query for {ip_address}")
        except Exception as e:
            if DEBUG_DNS_RESOLUTION:
                print(f"DEBUG DNS: dnspython error resolving {ip_address}: {e}")

        # Fallback to socket.gethostbyaddr if no PTR records found or dnspython failed
        if not resolved_hostnames:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                resolved_hostnames.append(hostname)
                if DEBUG_DNS_RESOLUTION:
                    print(f"DEBUG DNS: Resolved IP {ip_address} to hostname {hostname} via gethostbyaddr fallback")
            except socket.herror:
                if DEBUG_DNS_RESOLUTION:
                    print(f"DEBUG DNS: socket.gethostbyaddr could not resolve IP: {ip_address}")
    except Exception as e:
        if DEBUG_DNS_RESOLUTION:
            print(f"DEBUG DNS: General error resolving {ip_address}: {e}")

    return resolved_hostnames if resolved_hostnames else None


def parse_fw_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    groups = []
    group_map = {}  # To store groups by name for easy lookup
    child_parent_map = defaultdict(list)  # To track parent-child relationships

    group_sections = re.split(r'=+\n', content.strip())

    for section in group_sections:
        if not section.strip():
            continue

        lines = section.split('\n')
        group_name = None
        group_data = {
            'hosts': [],
            'networks': [],
            'ranges': [],
            'children': [],
            'ports': []  # Added for service groups
        }

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith('Grup ADI:') or line.startswith('Servis Grup ADI:'):
                group_name = line.split(':', 1)[1].strip()

            elif line.startswith('Host Obje Adi:'):
                parts = [p.strip() for p in line.split(',')]
                host_data = {}
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        host_data[key.lower().replace(' ', '_')] = value
                
                # Extract IP from hostname if present
                if 'host_obje_adi' in host_data:
                    host_name_for_ip_extraction = host_data['host_obje_adi']
                    extracted_ip = extract_ip_from_string(host_name_for_ip_extraction)
                    
                    # If an IP is extracted, try to resolve its hostname (PTR lookup)
                    if extracted_ip:
                        # Add the extracted IP to host_data if not already present as 'ip'
                        if 'ip' not in host_data:
                            host_data['ip'] = extracted_ip
                            
                        resolved_hostnames = resolve_ip(extracted_ip)
                        if resolved_hostnames:
                            host_data['ptr_hostnames'] = resolved_hostnames # Store as a list
                
                group_data['hosts'].append(host_data)

            elif line.startswith('Network Range Obje Adi:'):
                parts = [p.strip() for p in line.split(',')]
                range_data = {}
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        range_data[key.lower().replace(' ', '_')] = value
                group_data['ranges'].append(range_data)

            elif line.startswith('Network Obje Adi:'):
                parts = [p.strip() for p in line.split(',')]
                network_data = {}
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        network_data[key.lower().replace(' ', '_')] = value
                group_data['networks'].append(network_data)

            elif line.startswith('Diger Obje Adi:'):
                parts = [p.strip() for p in line.split(',')]
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        if (key != "Tipi"):
                            group_data['children'].append(value)
                            child_parent_map[value].append(group_name)
            
            elif line.strip().startswith('TCP Servis Adi:'):
                parts = [p.strip() for p in line.split(',')]
                port_data = {}
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        port_data[key.lower().replace(' ', '_')] = value
                group_data['ports'].append(port_data)

        if group_name:
            # Determine group type
            if group_data['ports']:
                group_type = 'Port Object Group'
            elif 'glb' in group_name.lower() or group_data['children']:
                group_type = 'Composite Group'
            elif group_data['hosts']:
                group_type = 'Host Group'
            elif group_data['networks']:
                group_type = 'Network Group'
            elif group_data['ranges']:
                group_type = 'Network Range Group'
            else:
                group_type = 'Unknown'

            group_obj = {
                'name': group_name,
                'type': group_type,
                'hosts': group_data['hosts'],
                'networks': group_data['networks'],
                'ranges': group_data['ranges'],
                'ports': group_data['ports'],
                'children': group_data['children'],
                'all_hosts': group_data['hosts'].copy(),  # Will include child hosts
                'all_networks': group_data['networks'].copy(),  # Will include child networks
                'all_ranges': group_data['ranges'].copy(),  # Will include child ranges
                'all_ports': group_data['ports'].copy()  # Will include child ports
            }

            groups.append(group_obj)
            group_map[group_name] = group_obj

    # Now process child relationships to aggregate all objects
    for group in groups:
        processed_children = set()
        queue = group['children'].copy()

        while queue:
            child_name = queue.pop(0)
            if child_name in processed_children:
                continue

            if child_name in group_map:
                child_group = group_map[child_name]

                # Add child's objects to parent's "all_" collections
                group['all_hosts'].extend(child_group['all_hosts'])
                group['all_networks'].extend(child_group['all_networks'])
                group['all_ranges'].extend(child_group['all_ranges'])
                group['all_ports'].extend(child_group['all_ports'])

                # Add child's children to the processing queue
                queue.extend(child_group['children'])
                processed_children.add(child_name)

    # After all groups are processed and child data aggregated, populate the search_terms
    for group in groups:
        search_terms = [group['name'], group['type']]

        # Add host details
        for host in group['all_hosts']:
            if 'host_obje_adi' in host:
                search_terms.append(host['host_obje_adi'])
            if 'ip' in host:
                search_terms.append(host['ip'])
            if 'ptr_hostnames' in host: # Check for the new key
                search_terms.extend(host['ptr_hostnames']) # Extend with all resolved hostnames
            if 'description' in host:
                search_terms.append(host['description'])

        # Add network details
        for network in group['all_networks']:
            if 'network_obje_adi' in network:
                search_terms.append(network['network_obje_adi'])
            if 'network' in network:
                search_terms.append(network['network'])
            if 'subnet_mask' in network:
                search_terms.append(network['subnet_mask'])
            if 'description' in network:
                search_terms.append(network['description'])

        # Add range details
        for r_range in group['all_ranges']:
            if 'network_range_obje_adi' in r_range:
                search_terms.append(r_range['network_range_obje_adi'])
            if 'range' in r_range:
                search_terms.append(r_range['range'])
            if 'description' in r_range:
                search_terms.append(r_range['description'])

        # Add port details
        for port in group['all_ports']:
            if 'tcp_servis_adi' in port:
                search_terms.append(port['tcp_servis_adi'])
            if 'port' in port:
                search_terms.append(port['port'])
            if 'aciklama' in port:
                search_terms.append(port['aciklama'])

        # Add child group names
        search_terms.extend(group['children'])

        # Clean and join search terms
        group['search_terms'] = ' '.join(filter(None, [str(s).strip() for s in search_terms]))

        if DEBUG_DNS_RESOLUTION:
            print(f"DEBUG SEARCH: Group '{group['name']}' search terms: {group['search_terms']}")

    return groups
