#!/usr/bin/python

VERSION = 'cbrcli version 1.5.0 (Promethium Blue)'
print VERSION
import os
import sys
import platform
import json
import re
import webbrowser
import struct
from hashlib import md5
from datetime import datetime, timedelta
from cbapi.response import CbResponseAPI, Process, Binary, Feed, Sensor
from cbapi.auth import Credentials, CredentialStore
from cbapi.errors import ServerError, CredentialError, ApiError
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import clear
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import style_from_dict
from prompt_toolkit.token import Token
from prompt_toolkit.history import InMemoryHistory, FileHistory
from prompt_toolkit.contrib.completers import WordCompleter, PathCompleter
from threading import Thread

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

reload(sys)
sys.setdefaultencoding('utf8')

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
            'endpoint',
            'watchlists',
            'signed',
            'original_filename',
            'cb_version',
            'os_type',
            'file_desc',
            'last_seen',
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
            'regmod',
            'filemod',
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
state['options'] = datetime.utcnow() - timedelta(days=1)
state['status_text'] = '[READY]'
state['display_filters'] = []
state['history_limit'] = 1000

default_opts = {
        'ignore_duplicates': {'type':'bool', 'value':False, 'description':'When set to True only unique rows within a fieldset will be shown'},
        'page_size': {'type':'int', 'value':20, 'description':'Number of results to display when using \'show\' and \'next\''},
        'wrap_output': {'type':'bool', 'value':True, 'description':'Truncate rows to fit on screen'},
        'timeframe': {'type':'string', 'value':"last 30 days", 'description':'Limit search to timeframe'},
        'regex_ignore_case': {'type':'bool', 'value':False, 'description':'Regexes are case sensitive'},
        'show_column_headers': {'type':'bool', 'value':True, 'description':'Show column headers when printing records'},
        'colorise_output': {'type':'bool', 'value':True, 'description':'Show colors in terminal (Will not work on windows unless using powershell)'},
        'align_columns': {'type':'bool', 'value':False, 'description':'Align columns in output'},
}

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
    
state['result'] = None
is_windows = 'windows' in platform.system().lower()
state['selected_mode'] = modes['process']
prompt_style = style_from_dict({
    Token.Toolbar: '#FFFFFF bg:#333333',
})

history = FileHistory('.history')
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

class colors:
    BLUE = '' if is_windows else '\033[94m'
    GREEN = '' if is_windows else '\033[92m'
    RED = '' if is_windows else '\033[91m'
    ORANGE = '' if is_windows else '\033[93m'
    ENDC = '' if is_windows else '\033[0m'

class nocolors:
    BLUE = ''
    GREEN = ''
    RED = ''
    ORANGE = ''
    ENDC = ''

state['color_scheme'] = colors if state['options']['colorise_output'] else nocolors

commands = {
    'version': "version\tPrint cbcli version",
    'mode': "mode <mode>\tSwitch to different search mode (most be one of: process, binary, sensor)",
    'search': "search <CB query string>\tSearch carbon black server",
    'filter': "filter <CB query string>\tFurther filter search query",
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
    'sort': "sort <field> [asc|desc]\tSort results by <field>",
    'open': "open <number>\tOpen event <number> in browser",
    'connect': "connect <number>\tGo live on host relating to record",
    'netconns': "netconns [number]\tShow network connections for displayed records, or specific record id if specified",
    'netconns-save': "netconns-save <filename>\tSave netconns to file",
    'regmods': "regmods [number]\tShow registry modifications for displayed records, or specific record id if specified",
    'regmods-save': "regmods-save [number] <filename>\tSave regmods to file",
    'filemods': "filemods [number]\tShow file modifications for displayed records, or specific record id if specified",
    'filemods-save': "filemods-save [number] <filename>\tSave filemods to file",
    'modloads': "modloads [number]\tShow modloads for displayed records, or specific record id if specified",
    'modloads-save': "modloads-save [number] <filename>\tSave modloads to file",
    'crossprocs': "crossprocs [number]\tShow cross processes for displayed records, or specific record id if specified",
    'crossprocs-save': "crossprocs-save [number] <filename>\tSave cross processes to file",
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
        if cmd in ('s', 'f', 'search', 'filter') and params:
            qry = params[-1]
            if params[-1].startswith('-'):
                qry = params[-1][1:]
            filters = [i for i in state['filters'][state['selected_mode']['name']]]
            for f in [i + ':' for i in state['selected_mode']['search_fields']] + ['AND', 'OR'] + filters:
                if qry.lower() in f.lower():
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
    def get_suggestion(self, cli, buffer, document):
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
            for field in state.get('facet_suggestions', []):
                if field.startswith(qry_val):
                    return Suggestion(field[len(qry_val):])
        if cmd == 'fieldset' and not is_windows:
            suggest_str = ' '.join(state['fieldsets'][state['selected_mode']['name']]['current'])
            from_user = ' '.join(params)
            if suggest_str.startswith(from_user):
                return Suggestion(suggest_str[len(' '.join(params)):])
        q = document.current_line.split(' ')[-1]

def get_bottom_toolbar_tokens(cli):
    return [(Token.Toolbar, state['status_text'])]

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
        print "Warning: You've set a goofy timeframe. I'm going to go ahead and use the last 30 days instead."
        timeframe = 'last 30 days'
    number, period = re.search('([0-9]+) ([^ ]+)', timeframe.lower()).groups()
    return datetime.utcnow() - timedelta(**{period:int(number)})

def do_search(qry):
    for f in state['filters'][state['selected_mode']['name']]:
        qry = qry.replace(f, state['filters'][state['selected_mode']['name']][f])
    qry_result = cb.select(state['selected_mode']['object'])
    if qry:
        try:
            qry_result = qry_result.where(qry)
        except ValueError:
            print ''.join((state['color_scheme'].RED, "Invalid query", state['color_scheme'].ENDC))
            qry = ''
    timeframe = parse_user_timeframe(state['options']['timeframe']['value'])
    if state['selected_mode']['name'] == 'process' and hasattr(qry_result, 'min_last_update'):
        qry_result.min_last_update(timeframe)

    qry_result.sort(state['selected_mode']['sort_field'])
    return qry, qry_result

def get_fields(result, state, expand_tabs=False):
    index = 1
    state['search_progress'] = 0
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
            state['search_progress'] = state['search_progress'] + 1
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
                    attr = str(getattr(r, field))
                    if regex:
                        result = regex.search(attr)
                        if result:
                            attr = result.group(0) if not result.groups() else result.groups()[0]
                        else:
                            attr = ''
                except AttributeError:
                    attr = ''
                if type(attr) == str:
                    fieldlist.append(attr.encode("utf-8", errors="ignore").replace('\n', ' '))
                else:
                    fieldlist.append(unicode(attr))
            if len(state['records']) > state['history_limit']:
                state['records'][len(state['records']) - state['history_limit']] = None
            if ignore_duplicates:
                h = md5(str(fieldlist)).digest()
                if h in history:
                    continue
                history.add(h)
            state['records'].append(r)
            yield index, fieldlist
            index += 1
    except ServerError as e:
        print "%sCarbon Black server returned an error. Check the server error logs for more information%s" % (state['color_scheme'].RED, state['color_scheme'].ENDC)

def save_results(filename, result, state, canary):
        total_results = len(result)
        with open(filename, 'w') as out:
            if state['options']['show_column_headers']:
                out.write('\t'.join(state['fieldsets'][state['selected_mode']['name']]['current']) + '\n')
            for index, fieldlist in get_fields(result, state):
                if canary['stop']:
                    state['status_text'] = '[EXPORT STOPPED]'
                    return
                state['status_text'] = 'Saving to %s (%d%%)' % (filename, int(float(state.get('search_progress', 0)) / total_results * 100))
                try:
                    out.write(unicode('\t'.join(fieldlist)).decode("utf-8", errors="ignore") + u'\n')
                except UnicodeDecodeError:
                    print fieldlist
            state['status_text'] = '[COMPLETE]'

def save_fieldsets(fieldsets):
    with open('.cbcli/fieldsets.json', 'w') as f:
        json.dump(fieldsets, f)

def print_rows(index, num_indent, rows, term_width=None):
    width = get_terminal_width()
    if state['options']['show_column_headers']['value'] and index == 1:
        rows = [state['fieldsets'][state['selected_mode']['name']]['current']] + rows
    paddings = [len(max((field[i] for field in rows), key=len)) for i in xrange(len(rows[0]))]
    if state['options']['show_column_headers']['value'] and index == 1:
        del(rows[0])
        if state['options']['align_columns']['value']:
            header_row = '  '.join((field + (' ' * (paddings[i] - len(field))) for i, field in enumerate(state['fieldsets'][state['selected_mode']['name']]['current'])))
        else:
            header_row = '  '.join(state['fieldsets'][state['selected_mode']['name']]['current'])
        header_row = ' ' * (num_indent + 1) + header_row
        print '%s%s%s' % (state['color_scheme'].GREEN, header_row[:width if state['options']['align_columns']['value'] else len(header_row)], state['color_scheme'].ENDC)
    for line_offset, fields in enumerate(rows):
        row_num_output = state['color_scheme'].BLUE + (' ' * (num_indent - len(str(index + line_offset)))) + str(index + line_offset) + state['color_scheme'].ENDC + ' '
        field_output = '  '.join([field + (' ' * (paddings[i] - len(field))) for i, field in enumerate(fields)])
        if not state['options']['wrap_output']['value']:
            field_output = field_output[:width-num_indent-2]
        print row_num_output + field_output

def result_pager(result, state):
    counter = 0
    num_indent = len(str(len(result)))
    lines = []
    width = get_terminal_width() + len(' ' * (num_indent))
    try:
        for index, fieldlist in get_fields(result, state, expand_tabs=True):
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
                yield
        if lines:
            print_rows(index - len(lines) + 1, num_indent, lines)
    except KeyboardInterrupt:
        pass

def print_facet_histogram(facets):
    fields = []
    state['facet_suggestions'] = []
    for entry in facets:
        fields.append((entry["name"], entry["ratio"], u"\u25A0"*(int(entry["percent"])/2)))
    if fields:
        max_fieldsize = max((len(i[0]) for i in fields))
    for f in fields:
        state['facet_suggestions'].append(f[0])
        line = "%*s: %5s%% %s%s%s" % (max_fieldsize, f[0], f[1], state['color_scheme'].GREEN, f[2], state['color_scheme'].ENDC)
        print line 

def parse_opt(t, s):
    if t == 'bool':
        if not s.lower() in ('true', 'false', 'on', 'off'):
            raise ValueError
        return s.lower() in ('true', 'on')
    if t == 'int':
        return int(s)
    return s

def format_netconn(nc, color=False):
    return "%s %15s -> %15s:%-5s (%s)" % (nc.timestamp, nc.local_ip, nc.remote_ip, nc.remote_port, nc.domain)

def format_regmod(regmod, color=False):
    line_color = ''
    if color:
        line_color = {'DeletedValue':state['color_scheme'].RED, 'DeletedKey':state['color_scheme'].RED, 'FirstWrote':state['color_scheme'].ENDC, 'CreatedKey':state['color_scheme'].GREEN}.get(regmod.type, '')
    return "%s%s %13s  %s%s" % (line_color, regmod.timestamp, regmod.type, regmod.path, state['color_scheme'].ENDC if color else '')

def format_filemod(filemod, color=False):
    line_color = ''
    if color and state['options']['colorise_output']['value']:
        line_color = {'Deleted':state['color_scheme'].RED, 'FirstWrote':state['color_scheme'].ENDC, 'CreatedFile':state['color_scheme'].GREEN}.get(filemod.type, '')
    return "%s%s %-11s %s%s" % (line_color, filemod.timestamp, filemod.type, filemod.path, state['color_scheme'].ENDC if color else '')

def format_modload(modload, color=False):
    return "%s  %s  %s" % (modload.timestamp, modload.md5, modload.path)

def format_crossproc(crossproc, color=False):
    line_color = ''
    if color and state['options']['colorise_output']['value']:
        line_color = {'ProcessOpen':state['color_scheme'].GREEN, 'ThreadOpen':state['color_scheme'].GREEN, 'RemoteThread':state['color_scheme'].RED}.get(crossproc.type, '')
    return "%s%s %-12s %s %s%s" % (line_color, crossproc.timestamp, crossproc.type, crossproc.target_md5, crossproc.target_path, state['color_scheme'].ENDC if color else '')

def format_children(child, color=False):
    return child.path

def format_parent(parent, color=False):
    return parent.path

def prefs_updated(state):
    state['color_scheme'] = colors if state['options']['colorise_output']['value'] else nocolors

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
            print "Please specify a mode from " + str([i for i in modes])
    @staticmethod
    def _search(cmd, params, state):
        state['facet_suggestions'] = []
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
        state['status_text'] = '%s > %d results for query: %s' % (state['options']['timeframe']['value'], result_count, qry)
        if state.get('display_filters'):
            state['status_text'] += ' (%d display filters active)' % len(state['display_filters'])
    _filter = _search
    @staticmethod
    def _back(cmd, params, state):
        state['qry_list'] = state['qry_list'][:-1]
        qry = ''
        if state['qry_list']:
            qry = state['qry_list'][-1]
        qry, state['result'] = do_search(qry)
        result_count = len(state['result'])
        state['status_text'] = 'Query: [%s] (%d results)' % (qry, result_count)
    @staticmethod
    def _show(cmd, params, state):
       if not state['result']:
           return "You haven't made a query yet."
       state['result_pager'] = result_pager(state['result'], state)
       try:
           state['result_pager'].next()
       except StopIteration:
           pass
    @staticmethod
    def _next(cmd, params, state):
        if not state.get('result_pager'):
            return "No results"
        try:
            state['result_pager'].next()
        except StopIteration:
            return "<No more results>"
    @staticmethod
    def _save(cmd, params, state):
        if not state['result']:
            return "No results"
        if not params:
            return "Please specify output filename"
        state['canary']['stop'] = False
        filename = ' '.join(params)
        t = Thread(target=save_results, args=(filename, state['result'], state, state['canary']))
        t.daemon = True
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
            print '%s%s%s' % (state['color_scheme'].ORANGE, 'Possible invalid fields: ' + ', '.join(warn_fields), state['color_scheme'].ENDC)
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
                print commands[key].split('\t')[0] + ' ' * (max_len - len(commands[key].split('\t')[0])), ' ', commands[key].split('\t')[1]
        else:
            print commands[params[0]] 
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
            state['quick_search_field'] = field
            print_facet_histogram(state['result'].facets(field)[field])
        except KeyboardInterrupt:
            return
        except ServerError:
            return "The server couldn't handle your request. This is likely an issue with the API provided by Carbon Black"
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
                print state.get('records', [])[index - 1] or "Record has expired"
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
                    print "%*s: %s" % (padding, field, str(getattr(state.get('records', [])[index - 1], field)))
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
                print '%*s: %s%s%s' % (max_opt_len, opt, state['color_scheme'].RED, str(state['options'][opt]['value']), state['color_scheme'].ENDC)
            return
        if not len(params) >= 2:
            return "Usage: <option> <value>"
        if state['options'].get(params[0]) == None:
            return "Invalid option"
        try:
            from_user = parse_opt(state['options'][params[0]]['type'], ' '.join(params[1:]))
            state['options'][params[0]]['value'] = from_user
            prefs_updated(state)
            print params[0] + ' => ' + str(state['options'][params[0]]['value'])
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
            print "%*s: %s" % (width, feed.display_name, result_count)
    @staticmethod
    def _sort(cmd, params, state):
        if not params:
            return "Please specify a sort field"
        if params[0] in state['selected_mode']['sortable_fields']:
            state['selected_mode']['sort_field'] = params[0] + ' ' + ('asc' if params[-1] == 'asc' else 'desc')
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
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'netconns', format_netconn, color=True):
                print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _netconns_save(cmd, params, state):
        try:
            record_id = int(params[0])
            del(params[0])
        except (ValueError, IndexError):
            record_id = None
        if not params:
            print "Please specify an output file"
            return
        try:
            with open(params[0], 'w') as f:
                records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
                for mod in get_mods(records, 'netconns', formatter=format_netconn):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _crossprocs(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'crossprocs', formatter=format_crossproc, color=True):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _crossprocs_save(cmd, params, state):
        try:
            record_id = int(params[0])
            del(params[0])
        except (ValueError, IndexError):
            record_id = None
        if not params:
            print "Please specify an output file"
            return
        try:
            with open(params[0], 'w') as f:
                records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
                for mod in get_mods(records, 'crossprocs', formatter=format_crossproc):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _modloads(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'modloads', formatter=format_modload, color=True):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _modloads_save(cmd, params, state):
        try:
            record_id = int(params[0])
            del(params[0])
        except (ValueError, IndexError):
            record_id = None
        if not params:
            print "Please specify an output file"
            return
        try:
            with open(params[0], 'w') as f:
                records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
                for mod in get_mods(records, 'modloads', formatter=format_modload):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _regmods(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'regmods', formatter=format_regmod, color=True):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _regmods_save(cmd, params, state):
        try:
            record_id = int(params[0])
            del(params[0])
        except (ValueError, IndexError):
            record_id = None
        if not params:
            print "Please specify an output file"
            return
        try:
            with open(params[0], 'w') as f:
                records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
                for mod in get_mods(records, 'regmods', formatter=format_regmod):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _filemods(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'filemods', formatter=format_filemod, color=True):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _filemods_save(cmd, params, state):
        try:
            record_id = int(params[0])
            del(params[0])
        except (ValueError, IndexError):
            record_id = None
        if not params:
            print "Please specify an output file"
            return
        try:
            with open(params[0], 'w') as f:
                records = [state.get('records', [])[record_id - 1]] if record_id else state.get('records', [])
                for mod in get_mods(records, 'filemods', formatter=format_filemod):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _children(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'children', formatter=format_children):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _parents(cmd, params, state):
        try:
            records = [state.get('records', [])[int(params[0]) - 1]] if params else state.get('records', [])
            for mod in get_mods(records, 'parents', formatter=format_parent):
                 print mod
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _children_save(cmd, params, state):
        if not params:
            return "Please specify an output file"
        try:
            with open(params[0], 'w') as f:
                for mod in get_mods(state.get('records', []), 'children', formatter=format_children):
                    f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
    @staticmethod
    def _parents_save(cmd, params, state):
        if not params:
            return "Please specify an output file"
        try:
            with open(params[0], 'w') as f:
                for mod in get_mods(state.get('records', []), 'parents', formatter=format_parent):
                    if mod == None:
                        f.write("Top of process tree" + '\n\n')
                    else:
                        f.write(mod + '\n')
        except (ValueError, IndexError):
            return "Invalid id"
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
        print VERSION
    @staticmethod
    def _debug(cmd, params, state):
        print dir(state.get('records', [])[int(params[0]) - 1])

def no_format(s, color=True):
    return s

def get_mods(records, mod_type, formatter=no_format, color=False):
    for mod_list in (getattr(i, mod_type, []) for i in records):
        for mod in mod_list:
            if not mod:
                continue
            yield formatter(mod, color=color)

state['running'] = True

profile = "default"
if len(sys.argv) > 1:
    profile = sys.argv[1]

# Fix to honour ignore_proxy config option
credentials = Credentials(CredentialStore('response').get_credentials(profile))
if credentials.get('ignore_system_proxy'):
    os.environ['NO_PROXY'] = credentials.get('url').split('//')[1].split('/')[0]

try:
    print "Connecting to server using profile '%s'" % profile
    cb = CbResponseAPI(profile=profile)
except CredentialError:
    if len(sys.argv) > 1:
        print "Profile '%s' could not be found. Please check it exists in the Carbon Black config" % sys.argv[1]
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
        print "Please create a profile in .carbonblack/credentials.response. An example file is provided in this directory"
    sys.exit(1)
except ApiError:
    print "Unable to connect using profile '%s'." % profile
    sys.exit(1)

state['feeds'] = [f for f in cb.select(Feed) if f.enabled]

clear()

while True:
    completer = QueryCompleter()
    suggester = QuerySuggester()
    try:
        from_user = prompt(u'(%s)> ' % state['selected_mode']['name'] if state['selected_mode'] else '-', 
                completer=completer,
                auto_suggest=suggester,
                get_bottom_toolbar_tokens=get_bottom_toolbar_tokens,
                history=history,
                refresh_interval=0.5,
                style=prompt_style).strip()
    except EOFError:
        state['canary']['stop'] = True
        print "Got ctrl+d, exiting..."
        break
    except KeyboardInterrupt:
        print '%s%s%s' % (state['color_scheme'].ORANGE, "Caught ctrl+c. Use 'exit' or ctrl+d to quit", state['color_scheme'].ENDC)
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
        print ''.join((state['color_scheme'].RED, "Query timed out", state['color_scheme'].ENDC))
    if out:
        print ''.join((state['color_scheme'].RED, out, state['color_scheme'].ENDC))
