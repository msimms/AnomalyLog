# -*- coding: utf-8 -*-
# 
# # MIT License
# 
# Copyright (c) 2019 Mike Simms
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import flask
import io
import mako
import os
import signal
import sys
import traceback
import Alert
import AuthLogMonitor

# Python 2 and Python 3 have different config parsers.
python_version = sys.version_info[0]
if python_version < 3:
    import ConfigParser
else:
    from configparser import ConfigParser

from mako.lookup import TemplateLookup
from mako.template import Template

g_flask_app = flask.Flask(__name__)
g_flask_app.secret_key = 'iTZL8ut2ggFBnvIBdCzW'
g_flask_app.url_map.strict_slashes = False
g_root_dir = os.path.dirname(os.path.abspath(__file__))
g_tempmod_dir = os.path.join(g_root_dir, 'tempmod')
g_mon = None

def signal_handler(signal, frame):
    print("Exiting...")
    global g_mon
    if g_mon is not None:
        g_mon.running = False
    sys.exit(0)

def get_hostname():
    """Returns the hostname, from /etc/hostname."""
    hostname = ""
    with open('/etc/hostname') as f:
        hostname = f.read().rstrip()
    if len(hostname) == 0:
        hostname = "Unknown"
    return hostname

def load_config(config_file_name):
    """Loads the configuration file."""
    if python_version < 3:
        with open(config_file_name) as f:
            sample_config = f.read()
        config = ConfigParser.RawConfigParser(allow_no_value=True)
        config.readfp(io.BytesIO(sample_config))
    else:
        config = ConfigParser()
        config.read(config_file_name)
    return config

@g_flask_app.route('/css/<file_name>')
def css(file_name):
    """Returns the CSS page."""
    try:
        print(file_name)
        return flask.send_from_directory('css', file_name)
    except:
        pass
    return ""

@g_flask_app.route('/')
def index():
    """Renders the index page."""
    global g_mon
    global g_root_dir

    # Format the user counts.
    user_counts_str = ""
    user_counts = g_mon.user_counts
    for user in user_counts:
        counts = user_counts[user]
        user_counts_str = user_counts_str + "<td>"
        user_counts_str = user_counts_str + user + "</td><td>"
        user_counts_str = user_counts_str + str(counts[0]) + "</td><td>"
        user_counts_str = user_counts_str + str(counts[1]) + "</td><td>"
        user_counts_str = user_counts_str + "</td><tr>\n"

    # Format the address counts.
    address_counts_str = ""
    address_counts = g_mon.address_counts
    for address in address_counts:
        counts = address_counts[address]
        address_counts_str = address_counts_str + "<td>"
        address_counts_str = address_counts_str + address + "</td><td>"
        address_counts_str = address_counts_str + str(counts[0]) + "</td><td>"
        address_counts_str = address_counts_str + str(counts[1]) + "</td><td>"
        address_counts_str = address_counts_str + "</td><tr>\n"

    # Render the page.
    html_file = os.path.join(g_root_dir, 'html', 'index.html')
    my_template = Template(filename=html_file, module_directory=g_tempmod_dir, input_encoding='utf-8', output_encoding='utf-8')
    return my_template.render(user_counts=user_counts_str, address_counts=address_counts_str)

def main():
    """Entry point for the app."""
    global g_mon
    global g_flask_app

    # Register the signal handler.
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", default=False, help="Prevents the app from going into the background.", required=False)
    parser.add_argument("--config", default="", help="Configuration file to be used.", required=False)
    parser.add_argument("--train-count", type=int, default=100, help="If non-zero, the model will be trained with the first N entries.", required=False)
    parser.add_argument("--verbose", action="store_true", default=False, help="Verbose mode.", required=False)
    parser.add_argument("--webui", action="store_true", default=False, help="If TRUE, starts the web-based user interface.", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        sys.exit(1)

    # If a configuration file was provided then load it.
    if len(args.config) > 0:
        config_obj = load_config(args.config)
    else:
        config_obj = None

    # Start the thread that monitors the auth log.
    print("Start auth log monitoring.")
    hostname = get_hostname()
    g_mon = AuthLogMonitor.AuthLogMonitor(config_obj, hostname, args.train_count, args.verbose)
    g_mon.start()

    # Start the web interface.
    if args.webui:
        print("Start the web interface.")
        mako.collection_size = 100
        mako.directories = "templates"
        g_flask_app.run(debug=args.debug)

if __name__ == '__main__':
    main()
