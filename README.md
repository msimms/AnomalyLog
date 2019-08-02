# Anomalous Log Monitor

## Description
This project implements machine learning, specifically anomaly detection, to actively monitor the Linux auth log for unusual activity.

## Installation
 * `git clone https://github.com/msimms/AnomalyLog`
 * `cd AnomalyLog`
 * `git submodule update --init`

## Execution
`python Monitor.py --train --config <config file>`

## Version History
In development.

## Tech
This software uses several other source projects to work properly:
* [LibIsolationForest](https://github.com/msimms/LibIsolationForest) - An implementation of the Isolation Forest anomaly detection algorithm.

## License
This software is released under the MIT license, see LICENSE for details.
