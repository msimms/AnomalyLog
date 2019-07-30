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

import re
import subprocess
import time
import numpy as np
from sklearn.cluster import KMeans

KEY_SUCCESS = "successful login"
KEY_IP = "ip"
KEY_USER = "user"
KEY_VALID_USER = "valid user"
KEY_TRUSTED_MACHINE = "trusted machine"

class AuthMonitor(object):
    """Class for monitoring the auth log."""

    def __init__(self, config_file, training):
        super(AuthMonitor, self).__init__()
        self.config_file = config_file
        self.training = training
        self.success_re_str = "(^.*\d+:\d+:\d+).*sshd.*Accepted password for (.*) from (.*) port.*"
        self.success_re = re.compile(self.success_re_str)
        self.failed_re_str = "(^.*\d+:\d+:\d+).*sshd.*Failed password for (.*) from (.*) port.*"
        self.failed_re = re.compile(self.failed_re_str)
        self.kmeans = KMeans(n_clusters=2)

    def train_model(self, features):
        print(features)
    
    def compare_against_model(self, features):
        print(features)

    def extract_features(self, line, valid_users):
        """Given a line from the auth log, extracts the features we will use in the model."""
        features = {}

        # Was it a successful login?
        success_match = self.success_re.match(line)
        if success_match:
            features[KEY_SUCCESS] = "true"
            features[KEY_IP] = success_match.group(3)
            user = success_match.group(2)
            features[KEY_USER] = user
            features[KEY_VALID_USER] = user in valid_users
            return features

        # Was it a failed login attempt?
        failed_match = self.failed_re.match(line)
        if failed_match:
            features[KEY_SUCCESS] = "false"
            features[KEY_IP] = failed_match.group(3)
            user = failed_match.group(2)
            features[KEY_USER] = user
            features[KEY_VALID_USER] = user in valid_users
            return features

        return features

    def list_users(self):
        # Return the list of user accounts from passwd.
        users = []

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
        # Get the list of valid users.
        valid_users = self.list_users()

        # Monitor the auth log.
        f = subprocess.Popen(['tail', '+f', '/var/log/auth.log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:

            # Do we have a new, valid line in the auth log? If so, extract featurse from it and either
            # compare it against the model or use it to train the model.
            line = f.stdout.readline()
            if line is not None and len(line) > 1:
                features = self.extract_features(line, valid_users)
                if len(features) > 0:
                    if self.training:
                        self.train_model(features)
                    else:
                        self.compare_against_model(features)

            # To keep us from busy looping, take a short nap.
            else:
                time.sleep(1)
