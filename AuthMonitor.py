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

KEY_SUCCESS = "successful login"
KEY_IP = "ip"
KEY_USER = "user"

class AuthMonitor(object):
    """Class for monitoring the auth log."""

    def __init__(self, training):
        super(AuthMonitor, self).__init__()
        self.training = training
        self.success_re_str = "(^.*\d+:\d+:\d+).*sshd.*Accepted password for (.*) from (.*) port.*"
        self.success_re = re.compile(self.success_re_str)
        self.failed_re_str = "(^.*\d+:\d+:\d+).*sshd.*Failed password for (.*) from (.*) port.*"
        self.failed_re = re.compile(self.failed_re_str)

    def train_model(self, featurs):
        pass
    
    def compare_against_model(self, featurs):
        pass

    def extract_features(self, line):
        """Given a line from the auth log, extracts the features we will use in the model."""
        features = {}

        success_match = self.success_re.match(line)
        if success_match:
            features[KEY_SUCCESS] = "true"
            features[KEY_IP] = success_match.group(1)
            features[KEY_USER] = success_match.group(2)
            return features

        failed_match = self.failed_re.match(line)
        if failed_match:
            features[KEY_SUCCESS] = "false"
            features[KEY_IP] = failed_match.group(1)
            features[KEY_USER] = failed_match.group(2)
            return features

        return features

    def start(self):
        f = subprocess.Popen(['less','+F','/var/log/auth.log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            line = f.stdout.readline()
            if line is not None and len(line) > 1:
                features = self.extract_features(line)
                if len(featurs) > 0:
                    if self.training:
                        self.train_model(features)
                    else
                        self.compare_against_model(features)
            else:
                time.sleep(1000)
