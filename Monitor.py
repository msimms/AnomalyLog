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
import io
import signal
import sys
import Alert
import AuthLogMonitor
import ConfigParser

g_mon = None

def signal_handler(signal, frame):
    print("Exiting...")
    global g_mon
    if g_mon is not None:
        g_mon.running = False

def load_config(config_file_name):
    """Loads the configuration file."""
    with open(config_file_name) as f:
        sample_config = f.read()
    config = ConfigParser.RawConfigParser(allow_no_value=True)
    config.readfp(io.BytesIO(sample_config))
    return config

def main():
    """Entry point for the app."""
    global g_mon

    # Register the signal handler.
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="", help="Configuration file to be used.", required=False)
    parser.add_argument("--train", action="store_true", default=False, help="If set, puts the application into training mode.", required=False)
    parser.add_argument("--train-count", type=int, default=100, help="If non-zero, the model will be trained with the first N entries.", required=False)

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

    # If we are not in training mode then we should have a model to load.
    if not args.train:
        if len(args.config) == 0:
            print("ERROR: A model was not provided. Consider training first.")
            sys.exit(0)

    g_mon = AuthLogMonitor.AuthLogMonitor(config_obj, args.train, args.train_count)
    g_mon.start()

if __name__ == '__main__':
    main()
