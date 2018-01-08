# cbrcli

## What is cbrcli

cbrcli was developed by security analysts to streamline the process of querying Carbon Black data, providing just the information you want in an easily readable format. It is not intended to completely replace the standard web interface, but to work alongside it providing a more customisable view of the data.

## Installing

cbrcli runs on Linux or Windows (probably OSX too), and installation instructions can be found below:

### Windows

Method 1: Cygwin (Recommended)
Cygwin is the recommended method of running cbrcli on windows as it will have all the features of the Linux version.

* Install Cygwin from https://cygwin.com/install.html
* When installing Cygwin, ensure that the python 2.7 and python pip packages are selected for installation
* Once installed, start cygwin and run `pip install cbapi`
* Download and extract cbrcli from the github page (https://github.com/ctxis/cbrcli)
* Navigate to the downloaded directory in cygwin, likely somewhere in /cygdrive/c/Users/yourusername/
* Follow the instructions here https://cbapi.readthedocs.io/en/latest/#api-credentials to set up your credentials
* Start cbrcli with `python cbrcli.py`

Method 2: Windows cmd
This method will work and is slightly simpler than the cygwin method, however the experience will not be as smooth and you won't get advantages like coloured output.

* Install Python 2.7 for windows (https://www.python.org/downloads/windows/) Note: Python 3.x will not work, you MUST use Python 2.7.
* Open a command prompt and run `C:\python27\scripts\pip.exe install cbapi`
* Download and extract cbrcli from the github page (https://github.com/ctxis/cbrcli)
* Navigate to the downloaded directory in the command prompt
* Open the file in `.carbonblack\credentials.response.example` in a text editor (not notepad), fill in the the required information and save as `credentials.response`
* Start cbrcli with `python cbrcli.py`

### Linux
Installation on Linux should be much simpler than Windows, just make sure you're running version 2,7 of Python and pip instead of Python 3.

* Run pip install cbapi
* Download and extract cbrcli from Github
* Follow the instructions here https://cbapi.readthedocs.io/en/latest/#api-credentials to set up your credentials
* cd into the cbrcli directory and run with `python cbrcli.py`

## In-program Help

The built-in `help` command can be used as a quick reference for commands in cbrcli, providing a full list of all available commands, along with a short discription and usage syntax.

## Searching

Searches in cbrcli use the exact same syntax as the search bar in the web UI. The application will automatically complete most valid search fields and other query syntax allowing you to quickly build up your query. There are two main keywords used to perform queries, `search` and `filter`. When initiating a new query, the `search` command will clear any existing results and perform a brand new query against the Carbon Black API. The `filter` command however, will append your query to the existing search terms, allowing you to narrow down your search criteria. Once a search has been performed, the status bar at the bottom of the screen will update to show the number of results returned by the query.
```
search parent_name:winword.exe AND process_name:powershell.exe
filter netconn_count:[1 TO *]
```

## Switching between Process and Binary Modes

cbrcli has two `modes` which determine whether to query for processes or binaries. The currently selected mode is displayed in the prompt and can be changed using the `mode` command followed by either `process` or `binary`. There is no difference to any of the commands you can perform between the two modes, however there will be different search terms available. The autocomplete functionality will only suggest valid fields for the current mode, for example `process_name` will only be available in `process` mode.
```
mode binary
mode process
```

## Displaying and Viewing Results

The `show` command can be used to display query results in a tabular form, pulling out just the fields you're interested in. By default, typing `show` will print a numbered list of the first 20 results that match the search criteria. Once the `show` command has been issued, further pages of results can be retrieved by pressing the return key. Results can be further filtered at any time, however the `show` command will need to be used again if the query is altered to retrieve the updated results.

If you would like to see more detailed information on any individual result displayed, you can enter the record number to the left of the result to see all of the fields printed to the screen. Alternatively, if you would prefer to use the web GUI for analysing individual events, you can use the `open` command followed by the record id to open the associated web page for the record in your default web browser. Multiple record ids can be used with the `open` command, separated by spaces, to open each one in a new tab using a single command.
Once search has been performed
```
search process_name:powershell.exe
show
open 1
open 2 3 4 5
```

## Fieldsets

cbrcli is designed to display only the information you're interested in when performing queries. The `fieldset` command can be used, followed by a space separated list of fields you're interested in to change the information displayed when the results are shown. If you find you are frequently using the same fieldsets, the currently active fieldset can be saved using `fieldset-save` followed by a name for the fieldset. Once saved, a fieldset can be re-loaded or deleted using the `fieldset-load` and `fieldset-remove` commands.
```
search process_name:cmd.exe
fieldset start username cmdline
show
```

## Summarising Results

Rather than sifting through many pages of results, you may instead wish to obtain a summary of the information returned. The `summarise` command followed by a field will display a histogram of the data. This can be very useful to identify uncommon values that may warrant further investigation. The `summarise` command will not affect your current query, and the `filter` command can be used to further refine your results based on any suspicious activity highlighted.
```
search process_name:svchost.exe
summarise parent_name
summarise process_md5
```

## Feeds

In addition to the `search` and `filter` commands, you can also use the `feed` command followed by a feed name to quickly display hits for any enabled feed. You can also use the `feeds` command to return a list of all enabled feeds along with a count of matching results for each.
feeds
feed Context IOC Feed

## Go Live

If you have Go Live enabled on your server, the `connect` command allows you to quickly open the Go Live webpage and connect to the host associated with a record. From here you can use all the functionality that Go Live provides.
```
search process_name:nc.exe
show
connect 1
```

## Exporting Results

The results of any query can be exported using the `save` command followed by an output filename. The results will begin saving to the specified output file and the status bar will update to provide a live status of the progress. The results will be saved in a tab separated format using the exact same fieldset and display filters that are active at the time, so make sure that the current fieldset contains all the fields you are interested in. While the export is in progress, cbrcli can be used as normal, however if any further queries are performed the status bar will no longer display the progress. The `stop` command can be issued at any time to abort a running export.
```
mode binary
search alliance_score_virustotal:[5 TO *]
fieldset md5 endpoint observed_filename
save suspicious_files.tsv
``` 

## Saved Queries

Common queries can be saved using the `query-save` command, so that they can be reused later. Previously saved queries will be suggested in the autocomplete when performing searches and can be used to simplify complex queries or share useful queries among multiple users of the tool. This feature could be used to provide a quick way of searching for processes or binaries with a given number of hits on virus total, or to group applications such as web browsers or archive tools into a single keyword.
```
search (process_name:iexplore.exe OR process_name:firefox.exe OR process_name:chrome.exe OR process_name:opera.exe)
query-save web_browsers
search web_browsers AND is_executable_image_filewrite:true
show
```

## Display Filters

The Carbon Black API does not support searching using regular expressions, however this can be achieved to an extent with cbrcli. Display filters are a client-side filter on a specific field, allowing results to be included or ignored based on whether a field matches a given regular expression. The `dfilter` command, followed by a field name and regular expression set a display filter to be applied to all further results until the `dfilter-clear` is used. By prefixing a field name with a hyphen, fields can be filtered out rather than filtered in.

Note: Care should be taken when using display filters as all work is done client-side. This means that all records are still retrieved from the Carbon Black server so queries with large numbers of results may take a long time to run, depending how many results are removed by the filter. It is recommended that the result set is filtered down as much as possible in the Carbon Black query before a display filter is used on the final result set.
### Search for a specific domain/url structure
```
search parent_name:outlook.exe AND process_name:iexplore.exe AND cmdline:*.info* AND cmdline:*index.html*
dfilter cmdline:http://[a-zA_Z0-9\-]\.info/[a-z]{5}-[0-9]{1,3}/index.html
show
```

## Custom Fields

Custom fields are a powerful feature which allow you to modify or normalise the fields that are displayed. When defining a fieldset, using the `fieldset` command, any field can be followed by a colon and a regular expression to display just the part of the field that matches the regular expression. This functionality becomes very useful when paired with the `ignore_duplicates` setting to normalise output.
### Get a unique list of ps1 files being executed:
```
search process_name:powershell.exe AND cmdline:*.ps1*
set ignore_duplicates on
fieldset cmdline:[^\\]*\.ps1
show
```

## Settings

cbrcli provides a range of settings that can be modified to change the behaviour of the program. The `set` command can be used on its own to list all available settings along with their values, or to set options if provided. The currently available commands are as follows:

* `truncate_to`: Truncate output rows to a fixed length to prevent wrapping
* `regex_ignore_case`: Dictates whether regular expressions should be case sensitive
* `page_size`: The number of results to display before returning control to the user
* `show_column_headers`: Whether to display selected field names when showing results
* `timeframe`: The timeframe to look over. e.g. `last 30 days`. 
* `colorise_output`: Controls whether colours are shown in the terminal. Only works in Linux/Cygwin.
