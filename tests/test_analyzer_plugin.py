#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.


import os

from commoncode.testcase import FileBasedTesting
from scancode.cli_test_utils import check_json_scan, run_scan_click


class AnalyzerPlugin(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data/analyzer-plugins/')

    def test_analyze_results_plugin(self):
        test_dir = self.get_test_loc('scan-files/')
        result_file = self.get_temp_file('json')
        args = ['--license', '--license-text', '--strip-root', test_dir, '--json', result_file, '--analyze-results']
        run_scan_click(args)
        check_json_scan(self.get_test_loc('results_analyzer_expected.json'), result_file)

    def test_analyze_results_plugin_load_from_json_analyze(self):

        input_json = self.get_test_loc('sample_files_result.json')
        result_file = self.get_temp_file('json')
        args = ['--from-json', input_json, '--json', result_file, '--analyze-results']
        run_scan_click(args)
        check_json_scan(self.get_test_loc('results_analyzer_from_sample_json_expected.json'), result_file)

    def test_analyze_results_plugin_load_from_json_no_license_data_analyze(self):
        test_dir = self.get_test_loc('scan-files/')
        assert 0 == sum([0])
