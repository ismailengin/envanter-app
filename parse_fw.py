# parse_fw.py
import re
from collections import defaultdict


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
            'children': []
        }

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith('Grup ADI:'):
                group_name = line.split(':', 1)[1].strip()

            elif line.startswith('Host Obje Adi:'):
                parts = [p.strip() for p in line.split(',')]
                host_data = {}
                for part in parts:
                    if ':' in part:
                        key, value = [x.strip().strip('"') for x in part.split(':', 1)]
                        host_data[key.lower().replace(' ', '_')] = value
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
                        print(f"Processing other object: {key} with value: {value}")
                        if (key != "Tipi"):
                            group_data['children'].append(value)
                            child_parent_map[value].append(group_name)

        if group_name:
            # Determine group type
            if 'glb' in group_name.lower() or group_data['children']:
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
                'children': group_data['children'],
                'all_hosts': group_data['hosts'].copy(),  # Will include child hosts
                'all_networks': group_data['networks'].copy(),  # Will include child networks
                'all_ranges': group_data['ranges'].copy()  # Will include child ranges
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

                # Add child's children to the processing queue
                queue.extend(child_group['children'])
                processed_children.add(child_name)

    return groups
