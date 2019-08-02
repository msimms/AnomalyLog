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

import inspect
import os
import re
import subprocess
import sys
import time
import ConfigParser

INVALID_USER_SUB_STR = "invalid user "

KEY_SUCCESS = "successful login"
KEY_ADDRESS = "addr"
KEY_USER = "user"
KEY_VALID_USER = "valid user"
KEY_USER_SUCCESS_COUNT = "user success count"
KEY_USER_FAIL_COUNT = "user fail count"
KEY_ADDR_SUCCESS_COUNT = "addr success count"
KEY_ADDR_FAIL_COUNT = "addr fail count"

# Locate and load the statistics module (the functions we're using in are made obsolete in Python 3, but we want to work in Python 2, also)
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
libforestdir = os.path.join(currentdir, 'LibIsolationForest', 'python2')
sys.path.insert(0, libforestdir)
from isolationforest import IsolationForest

class AuthLogMonitor(object):
    """Class for monitoring the auth log."""

    def __init__(self, config, training, train_count):
        super(AuthLogMonitor, self).__init__()
        self.running = True
        self.config = config
        self.training = training
        self.train_count = train_count
        self.success_re_str = "(^.*\d+:\d+:\d+).*sshd.*Accepted password for (.*) from (.*) port.*"
        self.success_re = re.compile(self.success_re_str)
        self.failed_re_str = "(^.*\d+:\d+:\d+).*sshd.*Failed password for (.*) from (.*) port.*"
        self.failed_re = re.compile(self.failed_re_str)
        self.user_counts = {}
        self.address_counts = {}
        self.model = IsolationForest.Forest(50, 10)

    def handle_anomaly(self, line, features, score):
        """Called when an anomaly is detected. Looks in the configuration to determien what action(s) to take."""
        if not self.config:
            print("ERROR: An anomaly was detected, but no action was taken because a configuration file was not specified.")
            return
        try:
            action_list_str = self.config.get('General', 'actions')
            action_list = action_list_str.split(',')
            for action in actions_list:
                msg = "An anomaly was detected:\n\tScore: " + str(score) + "\n\tLog Entry: " + line
                if action == 'Slack':
                    slack_token = self.config.get('Slack', 'token')
                    slack_channel = self.config.get('Slack', 'channel')
                    Alert.post_slack_msg(msg, slack_token, slack_channel)
        except ConfigParser.NoOptionError:
            print("ERROR: An anomaly was detected, but no actions were specified in the config.")
        except ConfigParser.NoSectionError:
            print("ERROR: An anomaly was detected, but no actions were specified in the config.")

    def train_model(self, features):
        """Adds the features to the training set."""
        sample = self.convert_features_to_sample(features)
        self.model.add_sample(sample)
    
    def compare_against_model(self, features):
        """Scores the features against the model."""
        sample = self.convert_features_to_sample(features)
        score = self.model.score(sample)
        return score

    def convert_features_to_sample(self, extracted_features):
        """Takes the features that were extracted or computed from the log file and converts
           it to a sample object that can be used by the IsolationForest."""
        sample = IsolationForest.Sample("")
        features = []
        features.append({KEY_SUCCESS: extracted_features[KEY_SUCCESS]})
        features.append({KEY_VALID_USER: extracted_features[KEY_VALID_USER]})
        features.append({KEY_USER_SUCCESS_COUNT: extracted_features[KEY_USER_SUCCESS_COUNT]})
        features.append({KEY_USER_FAIL_COUNT: extracted_features[KEY_USER_FAIL_COUNT]})
        features.append({KEY_ADDR_SUCCESS_COUNT: extracted_features[KEY_ADDR_SUCCESS_COUNT]})
        features.append({KEY_ADDR_FAIL_COUNT: extracted_features[KEY_ADDR_FAIL_COUNT]})
        sample.add_features(features)
        return sample

    def normalize_features(self, features):
        return features

    def calculate_features(self, features, valid_users):
        """Calculate additional features based on the ones extracted from the log file."""

        success = features[KEY_SUCCESS]
        user = features[KEY_USER]
        address = features[KEY_ADDRESS]

        # Is the provided user name a valid user?
        features[KEY_VALID_USER] = user in valid_users

        # Create record entries for the user and address, if necessary.
        if user not in self.user_counts:
            self.user_counts[user] = [0, 0]
        if address not in self.address_counts:
            self.address_counts[address] = [0, 0]

        # How many successful/failed login attempts for this user?
        # How many successful/failed login attempts for this source address?
        user_counts_value = self.user_counts[user]
        addr_counts_value = self.address_counts[address]
        if success:
            user_counts_value[0] = user_counts_value[0] + 1
            addr_counts_value[0] = addr_counts_value[0] + 1
        else:
            user_counts_value[1] = user_counts_value[1] + 1
            addr_counts_value[1] = addr_counts_value[1] + 1
        self.user_counts[user] = user_counts_value
        self.address_counts[user] = addr_counts_value
        features[KEY_USER_SUCCESS_COUNT] = user_counts_value[0]
        features[KEY_USER_FAIL_COUNT] = user_counts_value[1]
        features[KEY_ADDR_SUCCESS_COUNT] = addr_counts_value[0]
        features[KEY_ADDR_FAIL_COUNT] = addr_counts_value[1]

        return features

    def extract_features(self, line):
        """Given a line from the auth log, extracts the features we will use in the model."""
        features = {}

        # Was it a successful login?
        success_match = self.success_re.match(line)
        if success_match:
            features[KEY_SUCCESS] = True
            features[KEY_ADDRESS] = success_match.group(3)
            user = success_match.group(2)
            features[KEY_USER] = user
            return features

        # Was it a failed login attempt?
        failed_match = self.failed_re.match(line)
        if failed_match:
            features[KEY_SUCCESS] = False
            features[KEY_ADDRESS] = failed_match.group(3)
            user = failed_match.group(2)
            if user.find(INVALID_USER_SUB_STR) == 0:
                user = user[len(INVALID_USER_SUB_STR):]

            features[KEY_USER] = user
            return features

        return features

    def list_users(self):
        """Return the list of user accounts from passwd."""
        users = []

        # Read valid user names out of the passwd file.
        with open('/etc/passwd', mode='r') as pw_file:
            users_re = re.compile(r'[a-z0-9_-]{0,31}')
            contents_str = pw_file.read()
            contents = contents_str.split('\n')
            for line in contents:
                users_match = users_re.match(line)
                if users_match:
                    users.append(users_match.group(0))

        return users

    def start(self):
        num_training_samples = 0
        threshold = 0

        # If a configuration was provided, then read the threshold value from it.
        if self.config:
            try:
                threshold_str = self.config.get('Model', 'threshold')
                threshold = float(threshold_str)
                print("Using " + threshold_str + " as the threshold.")
            except ConfigParser.NoOptionError:
                print("ERROR: A threshold configuration was not provided.")
            except ConfigParser.NoSectionError:
                print("ERROR: A threshold configuration was not provided.")

        # Get the list of valid users.
        valid_users = self.list_users()

        # Monitor the auth log.
        f = subprocess.Popen(['tail', '+f', '/var/log/auth.log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while self.running:

            # Do we have a new, valid line in the auth log? If so, extract featurse from it and either
            # compare it against the model or use it to train the model.
            line = f.stdout.readline()
            if line is not None and len(line) > 1:

                # Extract features, calculate additional features, and normalize those features.
                features = self.extract_features(line)
                if len(features) > 0:

                    # Calculate derived features.
                    features = self.calculate_features(features, valid_users)

                    # Normalize features.
                    features = self.normalize_features(features)

                    # Either use the features for training or compare then against an existing model.
                    if self.training:
                        self.train_model(features)
                        num_training_samples = num_training_samples + 1
                    else:
                        score = self.compare_against_model(features)
                        print(features)
                        print(score)
                        if score > threshold:
                            self.handle_anomaly(line, featurse, score)

                    # Are we done training?
                    if self.training and self.train_count > 0 and num_training_samples > self.train_count:
                        self.model.create()
                        self.training = False

            # To keep us from busy looping, take a short nap.
            else:
                time.sleep(1)
