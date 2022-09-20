import re
import argparse
from os.path import exists
import xml.etree.ElementTree as ET

REGEX = r"(<Event>.*<\/Event>)"

EVENT_TYPE = {
    'ProcessCreate': '1',
    'NetworkConnect': '3',
    'SysmonState': '4',
    'ProcessTerminate': '5',
    'RawAccessRead': '9',
    'FileCreate': '11',
    'ConfigChange': '16',
    'FileDelete': '23',
}

def get_event_type(event_type_id):
    return list(EVENT_TYPE.keys())[list(EVENT_TYPE.values()).index(event_type_id)]

def get_system_data(event_data, attr_name):
    data = event_data.find(".//Data/[@Name='{}']".format(attr_name))
    if (data != None):
        return data.text
    else:
        return '-'

def print_green(str):
    return '\033[01m\033[92m {}\033[00m'.format(str)

def cmd_print(commands):
    for cmd in commands:
        print(cmd)
    print('\n')

def simple_print(events):
    for event in events:
        for k, v in event.items():
            print(print_green(k) + ': ' + v)

        print('\n')

def enum_users(events):
    users = []
    for event in events:
        for k, v in event.items():
            if k == 'User' and v != '-' and v not in users:
                users.append(event['User'])

    return users

def commands_only(events):
    commands = []
    for event in events:
        for k, v in event.items():
            if k == 'CommandLine' and v != '-':
                user_color = '\033[01m\033[91m' if event['User'] == 'root' else '\033[01m\033[92m'
                commands.append('\033[01m\33[34m{0}\033[00m ({1}{2}\033[00m): {3}'.format(event['UtcTime'], user_color, event['User'], event['CommandLine']))

    return commands

def process_sysmon_log(file):
    events = []

    file = open(file, 'r')
    lines = file.readlines()

    for line in lines:
        match = re.search(REGEX, line, re.MULTILINE)
        if not match:
            continue
        
        event_node = ET.ElementTree(ET.fromstring(match.group(0))).getroot()
        system_node = event_node.find('System')
        event_data = event_node.find('EventData')
        
        events.append({
            'EventId': system_node.find('EventID').text,
            'Version': system_node.find('Version').text,
            'EventType': get_event_type(system_node.find('Task').text),
            'Computer': system_node.find('Computer').text,
            'EventRecordID': system_node.find('EventRecordID').text,
            'UtcTime': get_system_data(event_data, 'UtcTime'),
            'ProcessGuid': get_system_data(event_data, 'ProcessGuid'),
            'ProcessId': get_system_data(event_data, 'ProcessId'),
            'Image': get_system_data(event_data, 'Image'),
            'FileVersion': get_system_data(event_data, 'Image'),
            'Description': get_system_data(event_data, 'Description'),
            'Product': get_system_data(event_data, 'Product'),
            'Company':  get_system_data(event_data, 'Company'),
            'OriginalFileName': get_system_data(event_data, 'OriginalFileName'),
            'CurrentDirectory': get_system_data(event_data, 'CurrentDirectory'),
            'User': get_system_data(event_data, 'User'),
            'LogonGuid': get_system_data(event_data, 'LogonGuid'),
            'LogonId': get_system_data(event_data, 'LogonId'),
            'TerminalSessionId': get_system_data(event_data, 'TerminalSessionId'),
            'IntegrityLevel': get_system_data(event_data, 'IntegrityLevel'),
            'Hashes': get_system_data(event_data, 'Hashes'),
            'ParentProcessGuid': get_system_data(event_data, 'ParentProcessGuid'),
            'ParentProcessId': get_system_data(event_data, 'ParentProcessId'),
            'ParentImage': get_system_data(event_data, 'ParentImage'),
            'CommandLine': get_system_data(event_data, 'CommandLine'),
            'ParentCommandLine': get_system_data(event_data, 'ParentCommandLine'),
            'ParentUser': get_system_data(event_data, 'ParentUser'),
        })

    return events

if __name__ == '__main__':    
    parser = argparse.ArgumentParser(description='Sysmon parser')
    parser.add_argument('-f', '--file', required=True, help='File to parse.')
    parser.add_argument('-e', '--event', help='Event type to filter.')
    parser.add_argument('-u', '--user', help='User to filter.')
    parser.add_argument('-p', '--process', help='Process ID to filter.')
    parser.add_argument('-pg', '--processg', help='Process GUID to filter.')
    parser.add_argument('-ppg', '--pprocessg', help='Parent Process GUID to filter.')
    parser.add_argument('-ep', '--elevated',  action='store_true', help='Elevated processes to filter.')
    parser.add_argument('-c', '--commands',  action='store_true', help='Commands only.')
    parser.add_argument('-eu', '--enumusers',  action='store_true', help='Enumerate users.')
    args = parser.parse_args()

    if not exists(args.file):
        print('Error: File does not exist.')

    events = process_sysmon_log(args.file)

    if args.enumusers:
        print('\033[01m\33[34mUsers:\033[00m ', end='')
        print(enum_users(events))
        print('')

    if args.event:
        events = [d for d in events if d['EventType'] in args.event]
    if args.user:
        events = [d for d in events if d['User'] in args.user]
    if args.process:
        events = [d for d in events if d['ProcessId'] in args.process]
    if args.processg:
        events = [d for d in events if d['ProcessGuid'] in args.processg]
    if args.pprocessg:
        events = [d for d in events if d['ParentProcessGuid'] in args.pprocessg]
    if args.elevated:
        events = [d for d in events if d['ParentUser'] != 'root' and d['ParentUser'] != '-' and d['User'] == 'root']
        # Should use LogonId

    if args.commands:
        cmd_print(commands_only(events))
    else:
        simple_print(events)