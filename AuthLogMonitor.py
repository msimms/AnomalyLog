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

import array
import inspect
import os
import re
import subprocess
import sys
import threading
import time
import Alert

python_version = sys.version_info[0]
if python_version < 3:
    import ConfigParser
else:
    from configparser import ConfigParser
    import statistics

# Config items in the General section.
CONFIG_SECTION_GENERAL = "General"
CONFIG_KEY_ACTIONS = "actions"
CONFIG_KEY_ALERT_ON_SUCCESSFUL_LOGIN = "only alert on successful login"
CONFIG_KEY_ALGORITHM = "algorithm"
CONFIG_KEY_SLACK_KEY = "key"
CONFIG_KEY_SLACK_CHANNEL = "channel"
CONFIG_ACTION_SLACK = 'Slack'

# Config items in the Training section.
CONFIG_SECTION_TRAINING = "Training"
CONFIG_KEY_TRAINING_COUNT = "count"

# Features
KEY_SUCCESS = "successful login" # TRUE if the OS allowed the login attempt, FALSE if it was denied
KEY_ADDRESS = "addr" # The address from which the login attempt is coming
KEY_USER = "user" # The user name of the user that is trying to log in
KEY_VALID_USER = "valid user" # This user is in the passwd file
KEY_USER_SUCCESS_COUNT = "user success count" # The number of times this user has successfully logged in
KEY_USER_FAIL_COUNT = "user fail count" # The number of times this user has failed to login
KEY_ADDR_SUCCESS_COUNT = "addr success count" # The number of times a successful login has come from this address
KEY_ADDR_FAIL_COUNT = "addr fail count" # The number of times a failed login has come from this address
KEY_ADDR_KNOWN_TO_USER = "addr known to user" # TRUE if the user has successfully logged in from this address before

INVALID_USER_SUB_STR = "invalid user "

NUM_SCORES = 100

# Locate and load the statistics module (the functions we're using in are made obsolete in Python 3, but we want to work in Python 2, also)
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
if python_version < 3:
    libforestdir = os.path.join(currentdir, 'LibIsolationForest', 'python2')
else:
    libforestdir = os.path.join(currentdir, 'LibIsolationForest', 'python3')
sys.path.insert(0, libforestdir)
from isolationforest import IsolationForest

class AuthLogMonitor(threading.Thread):
    """Class for monitoring the auth log."""

    def __init__(self, config, hostname, file_to_monitor, verbose):
        threading.Thread.__init__(self)
        self.running = True
        self.config = config
        self.hostname = hostname
        self.file_to_monitor = file_to_monitor
        self.verbose = verbose

        self.success_re_str = "(^.*\d+:\d+:\d+).*sshd.*Accepted password for (.*) from (.*) port.*"
        self.success_re = re.compile(self.success_re_str)
        self.failed_re_str = "(^.*\d+:\d+:\d+).*sshd.*Failed password for (.*) from (.*) port.*"
        self.failed_re = re.compile(self.failed_re_str)

        self.model = IsolationForest.Forest(50, 10)
        self.threshold = 0.9
        self.training = True
        self.num_training_samples = 0
        self.train_count = int(self.get_from_config(CONFIG_SECTION_TRAINING, CONFIG_KEY_TRAINING_COUNT))

        self.user_success_counts = {}
        self.address_success_counts = {}
        self.successful_user_addrs = {}

    def get_from_config(self, section, key):
        """Handles the differences between python2 and python3 in reading the config object."""
        try:
            if python_version < 3:
                return self.config.get(section, key)
            else:
                return self.config[section][key]
        except:
            pass
        return None

    def handle_anomaly(self, line, features, score):
        """Called when an anomaly is detected. Looks in the configuration to determien what action(s) to take."""
        if not self.config:
            print("ERROR: An anomaly was detected, but no action was taken because a configuration file was not specified.")
            return

        # Only alert on successful logins.
        alert_on_success = self.get_from_config(CONFIG_SECTION_GENERAL, CONFIG_KEY_ALERT_ON_SUCCESSFUL_LOGIN)
        if alert_on_success is not None:
            successful_logon = features[KEY_SUCCESS]
            if alert_on_success and not successful_logon:
                return

        # The Slack message we will use.
        slack_msg = "An anomaly was detected on " + self.hostname + ":\n\tScore: " + str(score) + "\n\tLog Entry: " + line

        # Handl each anomoly action.
        action_list_str = self.get_from_config(CONFIG_SECTION_GENERAL, CONFIG_KEY_ACTIONS)
        action_list = action_list_str.split(',')
        for action in action_list:
            if action == CONFIG_ACTION_SLACK:
                slack_token = self.get_from_config(CONFIG_ACTION_SLACK, CONFIG_KEY_SLACK_KEY)
                slack_channel = self.get_from_config(CONFIG_ACTION_SLACK, CONFIG_KEY_SLACK_CHANNEL)
                Alert.post_slack_msg(slack_msg, slack_token, slack_channel)

    def train_model(self, features):
        """Adds the features to the training set."""
        sample = self.convert_features_to_sample(features)
        self.model.add_sample(sample)

    def compare_against_model(self, features):
        """Scores the features against the model."""
        sample = self.convert_features_to_sample(features)
        score = self.model.normalized_score(sample)
        return score

    def convert_features_to_sample(self, extracted_features):
        """Takes the features that were extracted or computed from the log file and converts
           it to a sample object that can be used by the IsolationForest."""
        sample = IsolationForest.Sample("")
        features = []
        features.append({KEY_SUCCESS: int(extracted_features[KEY_SUCCESS])})
        features.append({KEY_VALID_USER: int(extracted_features[KEY_VALID_USER])})
        features.append({KEY_USER_SUCCESS_COUNT: extracted_features[KEY_USER_SUCCESS_COUNT]})
        features.append({KEY_USER_FAIL_COUNT: extracted_features[KEY_USER_FAIL_COUNT]})
        features.append({KEY_ADDR_SUCCESS_COUNT: extracted_features[KEY_ADDR_SUCCESS_COUNT]})
        features.append({KEY_ADDR_FAIL_COUNT: extracted_features[KEY_ADDR_FAIL_COUNT]})
        sample.add_features(features)
        return sample

    def calculate_features(self, features, valid_users):
        """Calculate additional features based on the ones extracted from the log file."""

        success = features[KEY_SUCCESS]
        user = features[KEY_USER]
        address = features[KEY_ADDRESS]

        # Is the provided user name a valid user?
        features[KEY_VALID_USER] = user in valid_users

        # Create record entries for the user and address, if necessary.
        if user not in self.user_success_counts:
            self.user_success_counts[user] = [0, 0]
        if address not in self.address_success_counts:
            self.address_success_counts[address] = [0, 0]
        if user not in self.successful_user_addrs:
            self.successful_user_addrs[user] = set()

        # How many successful/failed login attempts for this user?
        # How many successful/failed login attempts for this source address?
        user_counts_value = self.user_success_counts[user]
        addr_counts_value = self.address_success_counts[address]
        user_success_addrs = self.successful_user_addrs[user]
        if success:
            user_counts_value[0] = user_counts_value[0] + 1
            addr_counts_value[0] = addr_counts_value[0] + 1
            user_success_addrs.add(addr)
        else:
            user_counts_value[1] = user_counts_value[1] + 1
            addr_counts_value[1] = addr_counts_value[1] + 1
        self.user_success_counts[user] = user_counts_value
        self.address_success_counts[address] = addr_counts_value
        features[KEY_USER_SUCCESS_COUNT] = user_counts_value[0]
        features[KEY_USER_FAIL_COUNT] = user_counts_value[1]
        features[KEY_ADDR_SUCCESS_COUNT] = addr_counts_value[0]
        features[KEY_ADDR_FAIL_COUNT] = addr_counts_value[1]
        features[KEY_ADDR_KNOWN_TO_USER] = addr in user_success_addrs

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

    def analyze_using_anomoly_detection_algorithm(self, line, features):
        """Analysis algorithm 1"""

        anomolous = False

        # Either use the features for training or compare then against an existing model.
        if self.training:

            # Train the model.
            self.train_model(features)

            # Update the count of training samples.
            self.num_training_samples = self.num_training_samples + 1

            # If we're in verbose mode then print out the feature.
            if self.verbose:
                print(features)
                print("Used for training.")
        else:

            # Score the sample against the model.
            score = self.compare_against_model(features)

            # If we're over the threshold then handle the anomaly.
            if score > self.threshold:
                self.handle_anomaly(line, features, score)
                anomolous = True

            # If we're in verbose mode then print out the feature and it's score.
            if self.verbose:
                print(features)
                print(score)

        # Are we done training?
        if self.training and self.train_count > 0 and self.num_training_samples > self.train_count:
            self.model.create()
            self.training = False

            # If we're in verbose mode then let the user know we're done with training.
            if self.verbose:
                print("Training complete. Model generated.")

        return anomolous

    def analyze_using_simple_logic(self, line, features):
        """Analysis algorithm 2"""

        # If we're in verbose mode then print out the feature and it's score.
        if self.verbose:
            print(features)

        # Onlu interested in successful logins.
        if not features[KEY_SUCCESS]:
            return False

        # The access is valid if the user is known and has logged in from the given address before.
        if features[KEY_VALID_USER] and features[KEY_ADDR_KNOWN_TO_USER]:
            return False

        self.handle_anomaly(line, features, 1.0)
        return True

    def run(self):

        # Get the list of valid users.
        valid_users = self.list_users()

        # Which algorithm to use?
        algorithm = self.get_from_config(CONFIG_SECTION_GENERAL, CONFIG_KEY_ALGORITHM)
        if algorithm is None:
            algorithm = 'simple'
        else:
            algorithm = algorithm.lower()

        # Monitor the auth log.
        f = subprocess.Popen(['tail', '+f', self.file_to_monitor], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while self.running:

            # Do we have a new, valid line in the auth log? If so, extract featurse from it and either
            # compare it against the model or use it to train the model.
            try:
                temp_line = f.stdout.readline()
                if temp_line is not None and len(temp_line) > 1:

                    # Extract features, calculate additional features, and normalize those features.
                    line = str(temp_line)
                    features = self.extract_features(line)
                    if len(features) > 0:

                        # Calculate derived features.
                        features = self.calculate_features(features, valid_users)

                        # Analyze the sample.
                        if algorithm == 'simple':
                            self.analyze_using_simple_logic(line, features)
                        elif algorithm == 'forest':
                            self.analyze_using_anomoly_detection_algorithm(line, features)
                        else:
                            self.analyze_using_simple_logic(line, features)

                # To keep us from busy looping, take a short nap.
                else:
                    print("ERROR: Unable to read line from " + self.file_to_monitor + ".")
                    self.running = False

            except:
                print("ERROR: Unable to open the " + self.file_to_monitor + ".")
                self.running = False
