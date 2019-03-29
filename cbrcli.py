#!/usr/bin/python
from __future__ import (division, print_function, absolute_import, unicode_literals)

VERSION = 'cbrcli version 1.7.7 (Plutonium Eggplant)'
print(VERSION)
from six.moves import range
import os
import sys
import platform
import json
import re
import webbrowser
import struct
import sre_constants
import shutil
import time
import subprocess
from hashlib import md5
from datetime import datetime, timedelta
from cbapi.response import CbResponseAPI, Process, Binary, Feed, Sensor
from cbapi.live_response_api import LiveResponseError
from cbapi.errors import ServerError, CredentialError, ApiError
from threading import Thread
from collections import deque
from prompt_toolkit import prompt
try:
    from prompt_toolkit.shortcuts import clear
    from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.styles import Style
    from prompt_toolkit.formatted_text import HTML, ANSI
    from prompt_toolkit.history import InMemoryHistory, FileHistory
    from prompt_toolkit.completion import WordCompleter, PathCompleter
    from prompt_toolkit import PromptSession
except ImportError:
    print("Please upgrade your version of prompt_toolkit (pip install --upgrade prompt-toolkit)")
    sys.exit(1)

PYTHON_VERSION = sys.version_info[0]

modes = {
    'binary': {
        'object': Binary,
        'name': 'binary',
        'sort_field': 'server_added_timestamp desc',
        'sortable_fields': ['server_added_timestamp', 'digsig_sign_time', 'orig_mod_len', 'company_name', 'md5'],
        'default_fieldset': ['md5', 'observed_filename'],
        'fields': [
            'host_count',
            'digsig_result',
            'observed_filename',
            'product_version',
            'legal_copyright',
            'digsig_sign_time',
            'is_executable_image',
            'orig_mod_len',
            'is_64bit',
            'digsig_publisher',
            'group',
            'event_partition_id',
            'file_version',
            'company_name',
            'internal_name',
            'product_name',
            'digsig_result_code',
            'timestamp',
            'copied_mod_len',
            'server_added_timestamp',
            'facet_id',
            'md5',
            'hostname',
            'watchlists',
            'signed',
            'original_filename',
            'cb_version',
            'os_type',
            'file_desc',
            'last_seen',
            'webui_link',
        ]
    },
    'process': {
        'object': Process,
        'name': 'process',
        'sort_field': 'last_update desc',
        'sortable_fields': ['last_update', 'start', 'process_name', 'netconn_count', 'regmod_count', 'filemod_count', 'modload_count'],
        'default_fieldset': ['hostname', 'username', 'parent_name', 'process_name'],
        'fields': [
            'process_md5',
            'sensor_id',
            'filtering_known_dlls',
            'modload_count',
            'parent_unique_id',
            'emet_count',
            'cmdline',
            'filemod_count',
            'id',
            'parent_name',
            'parent_md5',
            'group',
            'parent_id',
            'hostname',
            'childproc_name',
            'last_update',
            'start',
            'emet_config',
            'regmod_count',
            'interface_ip',
            'process_pid',
            'username',
            'terminated',
            'process_name',
            'comms_ip',
            'last_server_update',
            'path',
            'netconn_count',
            'parent_pid',
            'crossproc_count',
            'segment_id',
            'host_type',
            'processblock_count',
            'os_type',
            'childproc_count',
            'unique_id'
            'domain',
            'ipaddr',
            'regmod',
            'filemod',
            'webui_link',
        ]
    },
    'sensor': {
        'object': Sensor,
        'name': 'sensor',
        'sort_field': '',
        'default_fieldset': ['computer_name', 'network_adapters:[^,]*', 'os_environment_display_string', 'last_checkin_time'],
        'sortable_fields': ['hostname', 'ip'],
        'search_fields': [
            'ip',
            'hostname',
            'groupid'
        ],
        'fields': [
            'boot_id',
            'build_id',
            'build_version_string',
            'clock_delta',
            'computer_dns_name',
            'computer_name',
            'computer_sid',
            'cookie',
            'display',
            'emet_dump_flags',
            'emet_exploit_action',
            'emet_is_gpo',
            'emet_process_count',
            'emet_report_setting',
            'emet_telemetry_path',
            'emet_version',
            'event_log_flush_time',
            'group_id',
            'id',
            'is_isolating',
            'last_checkin_time',
            'last_update',
            'license_expiration',
            'network_adapters',
            'network_isolation_enabled',
            'next_checkin_time',
            'node_id',
            'notes',
            'num_eventlog_bytes',
            'num_storefiles_bytes',
            'os_environment_display_string',
            'os_environment_id',
            'os_type',
            'parity_host_id',
            'physical_memory_size',
            'power_state',
            'registration_time',
            'restart_queued',
            'sensor_health_message',
            'sensor_health_status',
            'sensor_uptime',
            'shard_id',
            'status',
            'supports_2nd_gen_modloads',
            'supports_cblr',
            'supports_isolation',
            'systemvolume_free_size',
            'systemvolume_total_size',
            'uninstall',
            'uninstalled',
            'uptime',
        ]
    },
}

modes['process']['search_fields'] = modes['process']['fields']
modes['binary']['search_fields'] = modes['binary']['fields']

config_dir = '.cbcli'
opt_file = 'options.json'
state = {}
state['status_text'] = '[READY]'
state['display_filters'] = []
state['history_limit'] = 1000

default_opts = {
        'ignore_duplicates': {'type':'bool', 'value':False, 'description':'When set to True only unique rows within a fieldset will be shown'},
        'suggestion_size': {'type':'int', 'value':1000, 'description':'Number of field values to keep in memory for suggestions'},
        'page_size': {'type':'int', 'value':20, 'description':'Number of results to display when using \'show\' and \'next\''},
        'wrap_output': {'type':'bool', 'value':True, 'description':'Truncate rows to fit on screen'},
        'timeframe': {'type':'string', 'value':"last 30 days", 'description':'Limit search to timeframe'},
        'regex_ignore_case': {'type':'bool', 'value':False, 'description':'Regexes are case sensitive'},
        'show_column_headers': {'type':'bool', 'value':True, 'description':'Show column headers when printing records'},
        'colorise_output': {'type':'bool', 'value':True, 'description':'Show colors in terminal (Will not work on windows unless using powershell)'},
        'align_columns': {'type':'bool', 'value':False, 'description':'Align columns in output'},
        'timestamp_format': {'type':'string', 'value':'%Y-%m-%d %H:%M:%S', 'description':'Format for timestamp fields (Python datetime format string)'},
}

def u(s, encoding='utf8', errors='ignore'):
    if PYTHON_VERSION != 2:
        return str(s)
    if not type(s) == str:
        s = unicode(s)
    return unicode(s, encoding=encoding, errors=errors) if not isinstance(s, unicode) else s

def encode(s, encoding='utf8', errors='ignore'):
    return s.encode(encoding, errors=errors) if PYTHON_VERSION == 2 else s

def decode(s, encoding='utf8', errors='ignore'):
    return s.decode(encoding, errors=errors) if PYTHON_VERSION == 2 else s

try:
    with open(os.sep.join((config_dir, opt_file)), 'r') as f:
        state['options'] = json.load(f)
    for opt in default_opts:
        if opt not in state['options']:
            state['options'][opt] = default_opts[opt]
except IOError:
    state['options'] = default_opts
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    with open(os.sep.join((config_dir, opt_file)), 'w') as f:
        json.dump(state['options'], f)

class status_text:
    def __init__(self):
        self.qry = ''
        self.total_results = 0

    def update_query(self, index, total_searched, total_results=None, qry=None):
        self.qry = qry if not qry == None else self.qry
        if total_searched == None:
            total_searched = self.total_results
        self.total_results = total_results if not total_results == None else self.total_results
        st = '%s > %d of %d results for query: %s'
        st = st % (state['options']['timeframe']['value'], total_searched, self.total_results, self.qry)
        st += '' if index == total_searched else ' (%d suppressed)' % (total_searched - index)
        state['status_text'] = st

status = status_text()

state['result'] = None
is_windows = 'windows' in platform.system().lower()
state['selected_mode'] = modes['process']

state['qry_list'] = []
state['canary'] = {'stop':False}
result_ids = []
fieldset_file = "fieldsets.json"
filter_file = "filters.json"

if not os.path.exists(os.sep.join((config_dir, fieldset_file))):
    fieldsets = {}
    for mode in modes:
        default_fieldset = modes[mode]['default_fieldset']
        fieldsets[mode] = {'current':default_fieldset, 'default':default_fieldset}
    with open(os.sep.join((config_dir, fieldset_file)), 'w') as f:
        json.dump(fieldsets, f)

if not os.path.exists(os.sep.join((config_dir, filter_file))):
    filters = {}
    for mode in modes:
        filters[mode] = {}
    with open(os.sep.join((config_dir, filter_file)), 'w') as f:
        json.dump(filters, f)

with open(os.sep.join((config_dir, fieldset_file))) as fieldsets, open(os.sep.join((config_dir, filter_file))) as filters:
    state['fieldsets'] = json.load(fieldsets)
    state['filters'] = json.load(filters)

if not state['fieldsets']['process'].get('current'):
    state['fieldsets']['process']['current'] = state['fieldsets']['process']['default']
    state['fieldsets']['binary']['current'] = state['fieldsets']['binary']['default']

for mode in modes:
    if not state['filters'].get(mode):
        state['filters'][mode] = {}

color_schemes = {
    'default': {
        'blue': '\033[94m',
        'green': '\033[92m',
        'red': '\033[91m',
        'orange': '\033[93m',
        'endc': '\033[0m'
    },
    'no_colors': {
        'blue': '',
        'green': '',
        'red': '',
        'orange': '',
        'endc': ''
    }
}

state['color_scheme'] = 'default' if state['options']['colorise_output'] else 'no_colors'

def color(s, c):
    return s if is_windows or not c else '%s%s%s' % (color_schemes[state['color_scheme']][c], s, color_schemes[state['color_scheme']]['endc'])

commands = {
    'version': "version\tPrint cbcli version",
    'mode': "mode <mode>\tSwitch to different search mode (most be one of: process, binary, sensor)",
    'search': "search <CB query string>\tSearch carbon black server",
    'filter': "filter <CB query string>\tFurther filter search query",
    'bfilter': "bfilter <CB query string>\tReplace previous filter with this one",
    'fieldset': "fieldset <field1>[:regex] [field2][:regex], ...\tDefine which fields to show in output. Applies to show and save",
    'show': "show\tDisplay paged results in terminal (press <enter> to show more)",
    'save': "save <filename>\tSave results to <filename>",
    'fieldset-save': "fieldset-save <name>\tSave fieldset as <name>",
    'fieldset-load': "fieldset-load <name>\tLoad fieldset with <name>",
    'fieldset-remove': "fieldset-remove <name>\tRemove fieldset with <name>",
    'query-save': "query-save <name>\tSave current query as <name>",
    'query-remove': "query-remove <name>\tRemove query with <name>",
    'dfilter': "dfilter <field>:<filter>\tApply a regex display filter to query, applies to show and save commands",
    'dfilter-clear': "dfilter-clear\tClear all display filters",
    'dfilter-remove': "dfilter-remove\tRemove last display filter",
    'info': "info <number> [field1] [field2] ...\tDisplay all information on record, or specific fields if specified",
    'help': "help\tShow this help",
    'next': "n, next\tAfter using 'show', display next page of results",
    'summarise': "summarise <field>\tprint summary histogram of speficied field",
    'feed': "feed <feedname>\tPerform a search for specified feed hits",
    'feeds': "feeds\tList all feeds with hit counts",
    'back': "back\tRemove the most recent query from filter",
    'set': "set [<option> <value>]\tSet an option (or display settings if no option specified)",
    'group': "group <field>\tGroup results by <field>",
    'ungroup': "ungroup\tDisable grouping",
    'sort': "sort <field> [asc|desc]\tSort results by <field>",
    'open': "open <number>\tOpen event <number> in browser",
    'connect': "connect <number>\tGo live on host relating to record",
    'netconns': "netconns <number, *> [filter]\tShow network connections for displayed records, or specific record id if specified",
    'netconns-save': "netconns-save <number, *> <filename>\tSave netconns to file",
    'regmods': "regmods <number, *> [filter]\tShow registry modifications for displayed records, or specific record id if specified",
    'regmods-save': "regmods-save <number, *> <filename>\tSave regmods to file",
    'filemods': "filemods <number, *> [filter]\tShow file modifications for displayed records, or specific record id if specified",
    'filemods-save': "filemods-save <number, *> <filename>\tSave filemods to file",
    'modloads': "modloads <number, *> [filter]\tShow modloads for displayed records, or specific record id if specified",
    'modloads-save': "modloads-save <number, *> <filename>\tSave modloads to file",
    'crossprocs': "crossprocs <number, *> [filter]\tShow cross processes for displayed records, or specific record id if specified",
    'crossprocs-save': "crossprocs-save <number, *> <filename>\tSave cross processes to file",
    'children': "children [number]\tList child processes",
    'children-save': "children-save <filename>\tSave child processes to file",
    'parents': "parent [number]\tList parent processes",
    'parents-save': "parent-save <filename>\tSave parent processes to file",
    'exit': "exit\tTerminate cbcli",
}

def _get_terminal_size_windows():
    #https://gist.github.com/jtriley/1108174
    try:
        from ctypes import windll, create_string_buffer
        # stdin handle is -10
        # stdout handle is -11
        # stderr handle is -12
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom,
             maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
            sizex = right - left + 1
            sizey = bottom - top + 1
            return sizex
    except:
        pass
    return 80

def get_terminal_width():
    return int(_get_terminal_size_windows() if is_windows else os.popen('stty size', 'r').read().split(' ')[1])

class QueryCompleter(Completer):
    def get_completions(self, document, complete_event):
        split = document.current_line.split(' ')
        cmd, params = (split[0], split[1:])
        try:
            params = [int(cmd)] + params
            cmd = 'info'
        except ValueError:
            pass
        if cmd == 'mode' and params:
            for mode in modes:
                if mode.startswith(params[-1]):
                    yield Completion(mode, start_position=-len(params[-1]))
        if cmd in ('fs', 'fieldset') and params:
            for f in state['selected_mode']['fields']:
                if f.startswith(params[-1]):
                    yield Completion(f, start_position=-len(params[-1]))
        if cmd in ('s', 'f', 'search', 'filter', 'bfilter') and params:
            qry = params[-1]
            if params[-1].startswith('-'):
                qry = params[-1][1:]
            filters = [i for i in state['filters'][state['selected_mode']['name']]]
            for f in [i + ':' for i in state['selected_mode']['search_fields']] + ['AND', 'OR'] + filters:
                if f.lower().startswith(qry.lower()):
                    yield Completion(f, start_position=-len(qry))
        if cmd == 'info' and len(params) > 1:
            for f in state['selected_mode']['fields']:
                if f.lower().startswith(params[-1]):
                    yield Completion(f, start_position=-len(params[-1]))
        if cmd in ('fieldset-load', 'fieldset-remove') and params:
            for f in state['fieldsets'][state['selected_mode']['name']]:
                if f.startswith(params[-1]) and not (f == 'current' or cmd == 'fieldset-remove' and f == 'default'):
                    yield Completion(f, start_position=-len(params[-1]))
        if cmd in ('summarise', 'summarize', 'summary') and params:
            for f in state['selected_mode']['fields']:
                if f.startswith(params[-1]):
                    yield Completion(f, start_position=-len(params[-1]))
        if cmd == 'dfilter' and params:
            for f in state['selected_mode']['fields']:
                filter_str = ' '.join(params)
                if filter_str.startswith('-'):
                    filter_str = filter_str[1:]
                if f.startswith(filter_str):
                    yield Completion(f+':', start_position=-len(filter_str))
        if cmd == 'feed' and params:
            feed_name = ' '.join(params)
            for f in state['feeds']:
                if feed_name.lower() in f.display_name.lower():
                    yield Completion(f.display_name, start_position=-len(params[0]))
        if cmd == 'set' and len(params) == 1:
            for opt in state['options']:
                if opt.lower().startswith(params[0].lower()):
                     yield Completion(opt, start_position=-len(params[0]))
        if cmd == 'query-remove' and len(params) == 1:
            for f in state['filters'][state['selected_mode']['name']]:
                if f.lower().startswith(params[0].lower()):
                     yield Completion(f, start_position=-len(params[0]))
        if cmd == 'sort' and params:
            if len(params) == 1:
                for field in state['selected_mode']['sortable_fields']:
                    if field.lower().startswith(params[0].lower()):
                         yield Completion(field, start_position=-len(params[0]))
            if len(params) == 2:
                for v in ('asc', 'desc'):
                    if v.startswith(params[1].lower()):
                        yield Completion(v, start_position=-len(params[1]))
        if cmd == 'help' and params:
            if len(params) == 1:
                for field in commands:
                    if field.lower().startswith(params[0].lower()):
                        yield Completion(field, start_position=-len(params[0]))
            
class QuerySuggester(AutoSuggest):
    def get_suggestion(self, buffer, document):
        split = document.current_line.split(' ')
        cmd, params = (split[0], split[1:])
        if not params:
            for command in sorted(commands):
                if command.startswith(cmd):
                    return Suggestion(command[len(cmd):])
        if cmd in ('s', 'f', 'search', 'filter') and ':' in params[-1]:
            split = params[-1].split(':')
            qry_field, qry_val = split[0], ':'.join(split[1:])
            if qry_field == 'start' and qry_val.startswith('['):
                return Suggestion('[YYYY-MM-DDThh:mm:ss TO YYYY-MM-DDThh:mm:ss]'[len(qry_val):])
            for field in state.get('value_suggestions', []):
                if field.startswith(qry_val):
                    return Suggestion(field[len(qry_val):])
        if cmd == 'fieldset' and not is_windows:
            suggest_str = ' '.join(state['fieldsets'][state['selected_mode']['name']]['current'])
            from_user = ' '.join(params)
            if suggest_str.startswith(from_user):
                return Suggestion(suggest_str[len(' '.join(params)):])
        q = document.current_line.split(' ')[-1]

def is_numeric(s):
    try:
        int(s)
    except ValueError:
        return False
    return True

def get_toolbar():
    return state['status_text']

def parse_user_timeframe(timeframe):
    fields = timeframe.lower().split(' ')
    start_index = 0
    number = None
    for f in fields:
        try:
            number = int(f)
            break
        except ValueError:
            start_index += 1
    if not number or number < 0 or len(fields) < start_index+2 or fields[start_index+1] not in ('days', 'hours', 'minutes', 'weeks'):
        print("Warning: You've set a goofy timeframe. I'm going to go ahead and use the last 30 days instead.")
        timeframe = 'last 30 days'
    number, period = re.search('([0-9]+) ([^ ]+)', timeframe.lower()).groups()
    return datetime.utcnow() - timedelta(**{period:int(number)})

def do_search(qry):
    for f in state['filters'][state['selected_mode']['name']]:
        qry = qry.replace(f, state['filters'][state['selected_mode']['name']][f])
    qry_result = cb.select(state['selected_mode']['object'])
    timeframe = parse_user_timeframe(state['options']['timeframe']['value'])
    if state['selected_mode']['name'] == 'process' and hasattr(qry_result, 'min_last_update'):
        qry_result = qry_result.min_last_update(timeframe)
    if qry:
        try:
            qry_result = qry_result.where(qry)
        except ValueError:
            print(color("Invalid query", 'red'))
            qry = ''

    if state['selected_mode'].get('group_field'):
        try:
            qry_result = qry_result.group_by(state['selected_mode'].get('group_field', 'id'))
        except AttributeError:
            print("Warning: Unable to group by field %s" % state['selected_mode'].get('group_field'))
    qry_result = qry_result.sort(state['selected_mode']['sort_field'])
    return qry, qry_result

def get_fields(result, state, expand_tabs=False):
    index = 1
    state['records'] = []
    ignore_duplicates = state['options'].get('ignore_duplicates', {'value':False})['value']
    history = set()
    fields = state['fieldsets'][state['selected_mode']['name']]['current']
    regex_fields = []
    for f in fields:
        if ':' in f:
            split = f.split(':')
            try:
                rf = (split[0], re.compile(':'.join(split[1:]), re.IGNORECASE if state['options']['regex_ignore_case'] else 0))
            except re.error:
                rf = (split[0], None)
        else:
            rf = (f, None) 
        regex_fields.append(rf)
    try:
        for total_searched, r in enumerate(result):
            show = True
            neg_matches = ((df[0], df[1]) for df in state['display_filters'] if not df[2])
            for nm in neg_matches:
                if nm[0].search(str(getattr(r, nm[1]))):
                    show = False
            matches = ((df[0], df[1]) for df in state['display_filters'] if df[2])
            for m in matches:
                if not m[0].search(str(getattr(r, m[1]))):
                    show = False
            if not show:
                continue
            fieldlist = []
            for field, regex in regex_fields:
                try:
                    attr = getattr(r, field)
                    if regex:
                        attr_matches = []
                        if not type(attr) == list:
                            attr = [attr]
                        for attr_field in attr:
                            result = regex.search(encode(attr_field))
                            if result:
                                attr_matches.append(result.group(0) if not result.groups() else result.groups()[0])
                        attr = attr_matches
                except AttributeError:
                    attr = ''
                if not attr:
                    attr = ''
                if type(attr) == list:
                    fieldlist.append(u(', '.join((ai for ai in attr if ai))))
                elif type(attr) == datetime:
                    fieldlist.append(u(attr.strftime(state['options']['timestamp_format']['value'])))
                elif type(attr) == int:
                    fieldlist.append(str(attr))
                else:
                    fieldlist.append(u(attr).replace('\n', ' '))
            if len(state['records']) > state['history_limit']:
                state['records'][len(state['records']) - state['history_limit']] = None
            if ignore_duplicates:
                h = md5(str(fieldlist).encode('utf-8')).digest()
                if h in history:
                    continue
                history.add(h)
            state['records'].append(r)
            yield index, total_searched+1, [u(f) for f in fieldlist]
            index += 1
    except ServerError as e:
        print(color("Carbon Black server returned an error. Check the server error logs for more information", "red"))

running_exports = []
class result_exporter(Thread):
    def run(self):
        total_results = len(self.result)
        with open(self.filename[0], 'w') as out:
            if self.state['options']['show_column_headers']:
                out.write('\t'.join(self.state['fieldsets'][self.state['selected_mode']['name']]['current']) + '\n')
            for index, total_searched, fieldlist in get_fields(self.result, self.state):
                if self.canary['stop']:
                    self.state['status_text'] = '[EXPORT STOPPED]'
                    return
                self.state['status_text'] = 'Saving to %s (%d%%)' % (self.filename[0], int(float(total_searched) / total_results * 100))
                line = '\t'.join(fieldlist) + '\n'
                out.write(encode(line))
            self.state['status_text'] = '[COMPLETE]'
        running_exports.remove(self)

def save_fieldsets(fieldsets):
    with open('.cbcli/fieldsets.json', 'w') as f:
        json.dump(fieldsets, f)

token_regex = re.compile(r"[^\"\\ ]+")
def print_rows(index, num_indent, rows, term_width=None):
    width = get_terminal_width()
    if state['options']['show_column_headers']['value'] and index == 1:
        rows = [state['fieldsets'][state['selected_mode']['name']]['current']] + rows
    paddings = [len(max((field[i] for field in rows), key=len)) for i in range(len(rows[0]))]
    if state['options']['show_column_headers']['value'] and index == 1:
        del(rows[0])
        if state['options']['align_columns']['value']:
            header_row = '  '.join((field + (' ' * (paddings[i] - len(field))) for i, field in enumerate(state['fieldsets'][state['selected_mode']['name']]['current'])))
        else:
            header_row = '  '.join(state['fieldsets'][state['selected_mode']['name']]['current'])
        header_row = ' ' * (num_indent + 1) + header_row
        print('%s' % (color(header_row[:width if state['options']['align_columns']['value'] else len(header_row)], 'green')))
    for line_offset, fields in enumerate(rows):
        for field_index, field in enumerate(fields):
            if state['options']['suggestion_size'] == 0:
                break
            if state['fieldsets'][state['selected_mode']['name']]['current'][field_index] in ('start', 'last_updated'):
                continue
            tokens = (i.lower() for i in token_regex.findall(field))
            for token in tokens:
                if token not in state['value_suggestions']:
                    state['value_suggestions'].appendleft(token)
        row_num_output = (' ' * (num_indent - len(str(index + line_offset)))) + color(str(index + line_offset), 'blue') + ' '
        field_output = '  '.join([field + (' ' * (paddings[i] - len(field))) for i, field in enumerate(fields)])
        if not state['options']['wrap_output']['value']:
            field_output = field_output[:width-num_indent-2]
        print(row_num_output + field_output)

def result_pager(result, state):
    counter = 0
    total_searched = 0
    num_results = len(result)
    num_indent = len(str(num_results))
    lines = []
    width = get_terminal_width() + len(' ' * (num_indent))
    index = 0
    try:
        for index, total_searched, fieldlist in get_fields(result, state, expand_tabs=True):
            align_cols = state['options']['align_columns']['value'] and len(state['fieldsets'][state['selected_mode']['name']]['current']) > 1
            width = get_terminal_width() + len(' ' * (num_indent - len(str(index))) + str(index))
            if not align_cols:
                print_rows(index, num_indent, [fieldlist])
            else:
                lines.append(fieldlist)
            counter += 1
            if counter >= state['options']['page_size']['value']:
                if align_cols:
                    print_rows(index - state['options']['page_size']['value']+1, num_indent, lines)
                lines = []
                counter = 0
                yield index, total_searched
        if lines:
            print_rows(index - len(lines) + 1, num_indent, lines)
        yield index, len(result)
    except KeyboardInterrupt:
        pass

def print_facet_histogram(facets):
    fields = []
    for entry in facets:
        fields.append((entry["name"], entry["ratio"], u"\u25A0"*(int(int(entry["percent"])/2))))
    if fields:
        max_fieldsize = max((len(i[0]) for i in fields))
    for f in fields:
        state['value_suggestions'].appendleft(f[0])
        line = "%*s: %5s%% %s" % (max_fieldsize, f[0], f[1], color(f[2], 'green'))
        print(line)

def parse_opt(t, s):
    if t == 'bool':
        if not s.lower() in ('true', 'false', 'on', 'off'):
            raise ValueError
        return s.lower() in ('true', 'on')
    if t == 'int':
        return int(s)
    return s

def no_format(process, s, do_color=True):
    return s

def format_netconn(process, nc, do_color=False, event_id=''):
    return color(str(event_id) + " " if event_id else '', "blue" if do_color else None) + u"%s %15s:%-5s %s %15s:%-5s (%s)" % (nc.timestamp, nc.local_ip, nc.local_port, '->' if nc.direction == 'Outbound' else '<-', nc.remote_ip, nc.remote_port, nc.domain)

def format_regmod(process, regmod, do_color=False, event_id=''):
    line_color = ''
    if do_color:
        line_color = {'DeletedValue':'red', 'DeletedKey':'red', 'FirstWrote':'endc', 'CreatedKey':'green'}.get(regmod.type, '')
    return color(str(event_id) + " " if event_id else '', "blue") + color("%s %13s  %s", line_color) % (regmod.timestamp, regmod.type, regmod.path)

def format_filemod(process, filemod, do_color=False, event_id=''):
    line_color = ''
    if do_color and state['options']['colorise_output']['value']:
        line_color = {'deleted':'red', 'firstwrote':'endc', 'createdfile':'green', 'lastwrote':'endc'}.get(filemod.type, '')
    return color(str(event_id) + " " if event_id else '', "blue") + color("%s %-11s %s", line_color) % (filemod.timestamp, filemod.type, filemod.path)

def format_filemod_export(process, filemod, do_color=False, event_id=''):
    return '\t'.join((str(event_id), str(filemod.timestamp), process.hostname or "Unknown", process.username or "Unknown", process.process_name or "Unknown", filemod.type or "Unknown", filemod.path or "Unknown"))

def format_modload(process, modload, do_color=False, event_id=''):
    return color(str(event_id) + " " if event_id else '', "blue") + u"%s  %s  %s" % (modload.timestamp, modload.md5, modload.path)

def format_crossproc(process, crossproc, do_color=False, event_id=''):
    line_color = ''
    if color and state['options']['colorise_output']['value']:
        line_color = {'ProcessOpen':'green', 'ThreadOpen':'green', 'RemoteThread':'red'}.get(crossproc.type, '')
    return color(str(event_id) + " " if event_id else '', "blue") + color("%s %-12s %s %s", line_color) % (crossproc.timestamp, crossproc.type, crossproc.target_md5, crossproc.target_path)

def format_children(process, child, do_color=False):
    return child.path

def format_parent(process, parent, do_color=False):
    return parent.path

def prefs_updated(state):
    state['color_scheme'] = 'default' if state['options']['colorise_output']['value'] else 'no_colors'

def print_extra_data(params, state, data_type, formatter):
    filter_regex = None
    try:
        filter_regex = re.compile(params[1])
    except (IndexError, sre_constants.error):
        pass
    try:
        records = [state.get('records', [])[int(params[0]) - 1]] if params[0] != '*' else state.get('records', [])
        for mod in get_extra_data(records, data_type, formatter=formatter, do_color=True):
            if filter_regex:
                if filter_regex.search(mod):
                    print(mod)
            else:
                print(mod)
    except (ValueError, IndexError):
        return "Invalid id"

def save_extra_data(params, state, data_type, formatter):
    if len(params) < 2:
        return "Please specify a record id (or *) and output file"
    try:
        record_id = int(params[0])
    except (ValueError):
        record_id = None
    if not params:
        print("Please specify an output file")
        return
    try:
        with open(params[1], 'w') as f:
            records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
            for extra_data in get_extra_data(records, data_type, formatter=formatter):
                try:
                    f.write(encode(extra_data + '\n'))
                except ValueError as e:
                    print(e)
    except (ValueError, IndexError):
        return "Invalid id"

def get_extra_data(records, data_type, formatter=no_format, do_color=False):
    for event_id, data_list in enumerate((getattr(i, 'all_' + data_type)() if getattr(i, 'all_' + data_type) else getattr(i, data_type, []) for i in records)):
        for d in data_list:
            if not d:
                continue
            yield formatter(records[event_id], d, do_color=do_color, event_id=event_id+1 if len(records) > 1 else None)

def print_walking_results(proc, depth):
    print("[%d] %s%s" % (depth, "  "*depth, '\t'.join([str(getattr(proc, i, '')) for i in state['fieldsets'][state['selected_mode']['name']]['current']])))

state['value_suggestions'] = deque(maxlen=state['options']['suggestion_size']['value'])

class cbcli_cmd:
    @staticmethod
    def _invalid_cmd(cmd, params, state):
        if not cmd:
            return
        return "cbcli: %s: Command not found" % cmd
    @staticmethod
    def _mode(cmd, params, state):
        if params and params[0] in modes:
            state['selected_mode'] = modes.get(from_user.split(' ')[-1])
            state['result'] = None
            state['status_text'] = '[READY]'
        else:
            print("Please specify a mode from " + str([i for i in modes]))
    @staticmethod
    def _search(cmd, params, state):
        qry = ' '.join(from_user.split(' ')[1:])
        if cmd in ('s', 'search'):
            state['qry_list'] = []
        state['records'] = []
        if state['qry_list']:
            qry = state['qry_list'][-1] + ' AND ' + qry
        state['qry_list'].append(qry)
        qry, state['result'] = do_search(qry)
        try:
            result_count = len(state['result'])
        except ServerError:
            state['qry_list'].pop()
            state['result'] = None
            return "Invalid query"
        status.update_query(0,0, total_results=result_count, qry=qry)
        if state.get('display_filters'):
            state['status_text'] += ' (%d display filters active)' % len(state['display_filters'])
    _filter = _search
    @staticmethod
    def _bfilter(cmd, params, state):
        state['qry_list'] = state['qry_list'][:-1]
        qry = ''
        if state['qry_list']:
            qry = state['qry_list'][-1]
        cbcli_cmd._filter(cmd, params, state)
        
    @staticmethod
    def _back(cmd, params, state):
        state['qry_list'] = state['qry_list'][:-1]
        qry = ''
        if state['qry_list']:
            qry = state['qry_list'][-1]
        qry, state['result'] = do_search(qry)
        result_count = len(state['result'])
        status.update_query(0, 0, qry=qry, total_results=result_count)
    @staticmethod
    def _show(cmd, params, state):
        if not state['result']:
           return "No results"
        state['result_pager'] = result_pager(state['result'], state)
        try:
            index, progress = next(state['result_pager'])
            status.update_query(index, progress)
        except StopIteration:
            pass
    @staticmethod
    def _next(cmd, params, state):
        if not state.get('result_pager'):
            return "No results"
        try:
            index, progress = next(state['result_pager'])
            status.update_query(index, progress)
        except StopIteration:
            pass
    @staticmethod
    def _save(cmd, params, state):
        if not state['result']:
            return "No results"
        if not params:
            return "Please specify output filename"
        state['canary']['stop'] = False
        filename = ' '.join(params)
        t = result_exporter()
        t.filename = filename,
        t.result = state['result']
        t.state = state
        t.canary = state['canary']
        t.daemon=True
        running_exports.append(t)
        t.start()
    @staticmethod
    def _stop(cmd, params, state):
        state['canary']['stop'] = True
    @staticmethod
    def _fieldset(cmd, params, state):
        if not params:
            return "No fields specified"
        selected_fields = [i.split(':')[0] for i in params]
        warn_fields = []
        for f in selected_fields:
            if f not in state['selected_mode']['fields']:
                warn_fields.append(f)
        if warn_fields:
            print('%s' % (color('Possible invalid fields: ' + ', '.join(warn_fields), 'orange')))
        state['fieldsets'][state['selected_mode']['name']]['current'] = params
        save_fieldsets(state['fieldsets'])
    @staticmethod
    def _fieldset_save(cmd, params, state):
        if not params:
            return "Please specify a name for the fieldset"
        state['fieldsets'][state['selected_mode']['name']][params[0]] = state['fieldsets'][state['selected_mode']['name']]['current']
        save_fieldsets(state['fieldsets'])
    @staticmethod
    def _fieldset_load(cmd, params, state):
        if not params:
            return "Please specify a fieldset to load"
        state['fieldsets'][state['selected_mode']['name']]['current'] = state['fieldsets'][state['selected_mode']['name']].get(params[0]) or state['fieldsets'][state['selected_mode']['name']]['current']
        save_fieldsets(state['fieldsets'])
    @staticmethod
    def _fieldset_remove(cmd, params, state):
        if params[0] not in state['fieldsets'][state['selected_mode']['name']] or not params:
            return "No such fieldset"
        del(state['fieldsets'][state['selected_mode']['name']][params[0]])
        save_fieldsets(state['fieldsets'])
    @staticmethod
    def _help(cmd, params, state):
        if not params:
            max_len = sorted([len(commands[i].split('\t')[0]) for i in commands])[-1]
            for key in sorted((i for i in commands)):
                print(commands[key].split('\t')[0] + ' ' * (max_len - len(commands[key].split('\t')[0])), ' ', commands[key].split('\t')[1])
        else:
            print(commands[params[0]] )
    @staticmethod
    def _dfilter(cmd, params, state):
        if not params:
            return "Please specify a filter in the format <field>:<filter>"
        filter_str = ' '.join(params)
        regex = re.compile(filter_str, re.IGNORECASE if state['options']['regex_ignore_case'] else 0)
        if not ':' in filter_str or filter_str.split(':')[0] not in state['selected_mode']['fields'] and filter_str.split(':')[0][1:] not in state['selected_mode']['fields']:
            return "Invalid field"
        field, regex = (filter_str.split(':')[0], ':'.join(filter_str.split(':')[1:]))
        state['display_filters'].append((re.compile(regex, re.IGNORECASE if state['options']['regex_ignore_case'] else 0), field if not field.startswith('-') else field[1:], not field.startswith('-')))
    @staticmethod
    def _dfilter_clear(cmd, params, state):
        state['display_filters'] = []
    @staticmethod
    def _dfilter_remove(cmd, params, state):
        if state['display_filters']:
            state['display_filters'].pop()
    @staticmethod
    def _summarise(cmd, params, state):
        if not params:
            return "Please specify a field to summarise"
        if not state['result']:
            return "No results"
        try:
            field = ' '.join(params).strip()
            print_facet_histogram(state['result'].facets(field)[field])
        except KeyboardInterrupt:
            return
        except ServerError:
            return "The server couldn't handle your request."
        except AttributeError:
            return "Summarise unavailable"
    _summary = _summarize = _summarise
    @staticmethod
    def _info(cmd, params, state):
        if not params:
            return "Please specify a record id"
        if len(params) == 1:
            try:
                index = int(params[0])
                print(state.get('records', [])[index - 1] or "Record has expired")
            except ValueError:
                return "Invalid id"
            except IndexError:
                return "No such id"
        else:
            index = int(params[0])
            fields = [str(i) for i in params[1:]]
            padding = max(map(len, fields))
            for field in fields:
                try:
                    print("%*s: %s" % (padding, field, u(getattr(state.get('records', [])[index - 1], field))))
                except ValueError:
                    return "Invalid id"
                except IndexError:
                    return "No such id"
                except AttributeError:
                    return "No such field: " + field
    @staticmethod
    def _set(cmd, params, state):
        if not params:
            max_opt_len = max((len(i) for i in state['options']))
            for opt in state['options']:
                print('%*s: %s' % (max_opt_len, opt, color(str(state['options'][opt]['value']), 'red')))
            return
        if not len(params) >= 2:
            return "Usage: <option> <value>"
        if state['options'].get(params[0]) == None:
            return "Invalid option"
        try:
            from_user = parse_opt(state['options'][params[0]]['type'], ' '.join(params[1:]))
            state['options'][params[0]]['value'] = from_user
            prefs_updated(state)
            print(params[0] + ' => ' + str(state['options'][params[0]]['value']))
        except ValueError:
            return "Invalid value, %s takes a %s" % (params[0], state['options'][params[0]]['type'])
        with open(os.sep.join((config_dir, opt_file)), 'w') as f:
            json.dump(state['options'], f)
    @staticmethod
    def _feed(cmd, params, state):
        if not params:
            return "Please specify a feed"
        feed_name = ' '.join(params)
        for feed in state['feeds']:
            if feed.display_name == feed_name:
                qry = '(alliance_score_%s:*)' % feed.name.lower()
                state['qry_list'] = [qry]
                qry, state['result'] = do_search(qry)
                result_count = len(state['result'])
                state['status_text'] = 'Query: [%s] (%d results)' % (qry, result_count)
                return
        return "Invalid feed"
    @staticmethod
    def _feeds(cmd, params, state):
        width = max((len(f.display_name) for f in state['feeds']))
        for feed in state['feeds']:
            qry = '(alliance_score_%s:*)' % feed.name.lower()
            qry, result = do_search(qry)
            result_count = len(result)
            print("%*s: %s" % (width, feed.display_name, result_count))
    @staticmethod
    def _ungroup(cmd, params, state):
        state['selected_mode']['group_field'] = None
    @staticmethod
    def _group(cmd, params, state):
        if not params:
            return "Please specify a field to group by"
        state['selected_mode']['group_field'] = params[0]
    @staticmethod
    def _sort(cmd, params, state):
        if not params:
            return "Please specify a sort field"
        if params[0] in state['selected_mode']['sortable_fields']:
            state['selected_mode']['sort_field'] = params[0] + ' ' + ('asc' if params[-1] == 'asc' else 'desc')
        else:
            return "Unable to sort by %s" % params[0]
    @staticmethod
    def _open(cmd, params, state):
        if not params:
            return "Please specify a record id to open"
        savout = os.dup(2)
        os.close(2)
        os.open(os.devnull, os.O_RDWR)
        try:
            indexes = (int(i) for i in params)
            urls = [state.get('records', [])[i - 1].webui_link for i in indexes]
            if not urls:
                return "Record has expired"
            for url in urls:
                webbrowser.open(url)
        except (IndexError, ValueError):
            return "Invalid id"
        finally:
            os.dup2(savout, 2)
    @staticmethod
    def _connect(cmd, params, state):
        savout = os.dup(2)
        os.close(2)
        os.open(os.devnull, os.O_RDWR)
        try:
            record = state.get('records', [])[int(params[0])]
            url = "https://%s/#/live/%d" % (record.webui_link.split('/')[2], record.sensor_id)
            webbrowser.open(url)
        except (IndexError, ValueError):
            return "Invalid id"
        finally:
            os.dup2(savout, 2)
    @staticmethod
    def _netconns(cmd, params, state):
        return print_extra_data(params, state, 'netconns', format_netconn)
    @staticmethod
    def _netconns_save(cmd, params, state):
        return save_extra_data(params, state, 'netconns', format_netconn)
    @staticmethod
    def _crossprocs(cmd, params, state):
        return print_extra_data(params, state, 'crossprocs', format_crossproc)
    @staticmethod
    def _crossprocs_save(cmd, params, state):
        return save_extra_data(params, state, 'crossprocs', format_crossproc)
    @staticmethod
    def _modloads(cmd, params, state):
        return print_extra_data(params, state, 'modloads', format_modload)
    @staticmethod
    def _modloads_save(cmd, params, state):
        return save_extra_data(params, state, 'modloads', format_modload)
    @staticmethod
    def _regmods(cmd, params, state):
        return print_extra_data(params, state, 'regmods', format_regmod)
    @staticmethod
    def _regmods_save(cmd, params, state):
        return save_extra_data(params, state, 'regmods', format_regmod)
    @staticmethod
    def _filemods(cmd, params, state):
        return print_extra_data(params, state, 'filemods', format_filemod)
    @staticmethod
    def _filemods_save(cmd, params, state):
        return save_extra_data(params, state, 'filemods', format_filemod_export)
    @staticmethod
    def _children(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for proc in records:
                 proc.walk_children(print_walking_results)
        except (ValueError, IndexError):
            return "Invalid id"
        except KeyboardInterrupt:
            return "Caught ctrl+c. Use 'exit' or ctrl+d to quit"
    @staticmethod
    def _parents(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for proc in records:
                 proc.walk_parents(print_walking_results)
        except (ValueError, IndexError):
            return "Invalid id"
        except KeyboardInterrupt:
            return "Caught ctrl+c. Use 'exit' or ctrl+d to quit"
    @staticmethod
    def _children_save(cmd, params, state):
        if not params:
            return "Please specify an output file"
        try:
            with open(params[0], 'w') as f:
                for mod in get_extra_data(state.get('records', []), 'children', formatter=format_children):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
        except KeyboardInterrupt:
            return "Caught ctrl+c. Use 'exit' or ctrl+d to quit"
    @staticmethod
    def _parents_save(cmd, params, state):
        if not params:
            return "Please specify an output file"
        try:
            with open(params[0], 'w') as f:
                for mod in get_extra_data(state.get('records', []), 'parents', formatter=format_parent):
                    if mod == None:
                        f.write("Top of process tree" + '\n\n')
                    else:
                        f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
        except KeyboardInterrupt:
            return "Caught ctrl+c. Use 'exit' or ctrl+d to quit"
    @staticmethod
    def _query_save(cmd, params, state):
        if not state['qry_list']:
            return "You must perform a query first"
        if not params:
            return "Please specify a name for this query"
        state['filters'][state['selected_mode']['name']][params[0]] = state['qry_list'][-1]
        with open(os.sep.join((config_dir, filter_file)), 'w') as f:
            json.dump(state['filters'], f)
    @staticmethod
    def _query_remove(cmd, params, state):
        if not params:
            return "Please specify a query to remove"
        if state['filters'][state['selected_mode']['name']].get(params[0]) == None:
            return "That saved query does not exist"
        del(state['filters'][state['selected_mode']['name']][params[0]])
        with open(os.sep.join((config_dir, filter_file)), 'w') as f:
            json.dump(state['filters'], f)
    @staticmethod
    def _exit(cmd, params, state):
        state['running'] = False
    @staticmethod
    def _version(cmd, params, state):
        print(VERSION)
    @staticmethod
    def _shell(cmd, params, state):
        if not len(params):
            return "No host specified"
        hostname = params[0]
        print(color("Connecting to %s" % hostname, 'green'))
        shell = live_shell(hostname)
        while True:
            try:
                from_user = prompt(u'cb@%s:%s # ' % (hostname, shell.path), history=shell_history)
            except EOFError:
                break
            if not from_user:
                continue
            if from_user == 'exit':
                break
            parts = from_user.split(' ')
            try:
                output = getattr(shell, '_' + parts[0])(parts[0], parts[1:], state)
            except AttributeError:
                print(color('Unknown command: %s' % parts[0], 'red'))
        shell.session.close()
        print("Disconnected from %s" % hostname)
        
    @staticmethod
    def _debug(cmd, params, state):
        print(dir(state.get('records', [])[int(params[0]) - 1]))

class live_shell:
    def __init__(self, hostname):
        sensor = cb.select(Sensor).where("hostname:%s" % hostname).first()
        if sensor:
            self.session = sensor.lr_session()
            self.path = 'c:'
            self.path_sep = re.compile('[\\/]')
    
    def list_dir(self, path):
        d = self.get_absolute_path(' '.join(params))
        try:
            for row in self.session.list_directory(d):
                print(row.get('filename'))
        except LiveResponseError:
            print ("%s: Path not found" % d)

    def file_listing(self, file_detail):
        last_write = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_detail.get('last_write_time', 0)))
        created = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_detail.get('create_time', 0)))
        size = '<dir>' if 'DIRECTORY' in file_detail.get('attributes', []) else str(file_detail.get('size', -1))
        filename = file_detail.get('filename', '')
        return [created, last_write, size, filename]

    def format_files(self, file_list):
        if not file_list:
            return []
        padding = [0 for i in file_list]
        for row in file_list:
            for i, value in enumerate(row):
                if len(value) > padding[i]:
                    padding[i] = len(value)
        for row in file_list:
            for i, value in enumerate(row):
                row[i] = row[i] + (' ' * (padding[i] - len(row[i])))
        return file_list

    def _ls(self, cmd, params, state):
        path = self.absolute_path(self.path + '\\' + ' '.join(params))
        try:
            dir_listing = self.session.list_directory(path)
            rows = []
            for row in dir_listing:
                rows.append(self.file_listing(row))
            for row in self.format_files(rows):
                print('   '.join(row))
        except LiveResponseError:
            print(color('%s: Path not found' % path, 'red'))
    _dir = _ls

    def stat(self, path):
        path = path.strip('\\')
        try:
            info = self.session.list_directory(path)
        except LiveResponseError:
            return None
        return 'DIRECTORY' in info[0].get('attributes', [])

    def fix_path(self, path):
        path = path.replace('\\', os.path.sep)
        path = os.path.normpath(path)
        return path.replace(os.path.sep, '\\')

    def absolute_path(self, path):
        if ':' in path:
            return path
        full_path = '\\'.join((self.path, path.replace('/', '\\').strip('\\')))
        drive = full_path[0]
        full_path = self.fix_path(full_path)
        return full_path if len(full_path) > 1 else drive + ':'

    def _cd(self, cmd, params, state):
        path = self.absolute_path(' '.join(params))
        if self.stat(path):
            self.path = path
        else:
            print(color('%s: Path not found' % path, 'red'))

    def _cat(self, cmd, params, state):
        path = self.absolute_path(' '.join(params))
        try:
            shutil.copyfileobj(self.session.get_raw_file(path), sys.stdout)
        except LiveResponseError:
            print(color('%s: Path not found' % path, 'red'))

state['running'] = True

profile = "default"
if len(sys.argv) > 1:
    profile = sys.argv[1]

try:
    print("Connecting to server using profile '%s'" % profile)
    cb = CbResponseAPI(profile=profile)
except CredentialError:
    if len(sys.argv) > 1:
        print("Profile '%s' could not be found. Please check it exists in the Carbon Black config" % sys.argv[1])
    else:
        if not os.path.exists('.carbonblack'):
            os.makedirs('.carbonblack')
        if not os.path.exists(os.sep.join(('.carbonblack', 'credentials.response.example'))):
            with open(os.sep.join(('.carbonblack', 'credentials.response.example')), 'w') as f:
                f.write("[default]\n")
                f.write("url=https://path-to-server\n")
                f.write("token=your_token\n")
                f.write("ssl_verify=False\n")
                f.write("ignore_system_proxy=True")
        print("Please create a profile in .carbonblack/credentials.response. An example file is provided in this directory")
    sys.exit(1)
except ApiError:
    print("Unable to connect using profile '%s'." % profile)
    sys.exit(1)

state['feeds'] = [f for f in cb.select(Feed) if f.enabled]

clear()

history = FileHistory('.history')
shell_history = FileHistory('.shell_history')
session = PromptSession(
        history=history,
        auto_suggest=QuerySuggester()
        )

toolbar_style = Style.from_dict({
    'bottom-toolbar':      '#333333 bg:#ffffff',
    'bottom-toolbar.text': '#333333 bg:#ffffff',
})

while state['running']:
    completer = QueryCompleter()
    suggester = QuerySuggester()
    try:
        from_user = session.prompt(u'(%s)> ' % state['selected_mode']['name'] if state['selected_mode'] else '-', 
                completer=completer,
                auto_suggest=suggester,
                bottom_toolbar=get_toolbar,
                style=toolbar_style,
                refresh_interval=0.5 if running_exports else None,
                ).strip()
    except EOFError:
        state['canary']['stop'] = True
        print("Got ctrl+d, exiting...")
        break
    except KeyboardInterrupt:
        print('%s' % (color("Caught ctrl+c. Use 'exit' or ctrl+d to quit", 'orange')))
        continue
    cmd = from_user.split(' ')[0]
    params = from_user.split(' ')[1:]
    try:
        params = [int(cmd)] + params
        cmd = "info"
    except ValueError:
        pass
    if not cmd and state['result']:
        cmd = 'next'
    try:
        out = getattr(cbcli_cmd, '_' + cmd.replace('-', '_'), cbcli_cmd._invalid_cmd)(cmd=cmd, params=params, state=state)
    except ApiError:
        print(color("Query timed out", 'red'))
        continue
    if out:
        print(color(out, 'red'))
