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
import attr

from commoncode.testcase import FileBasedTesting
from commoncode.resource import Resource
from commoncode.resource import build_attributes_defs
from scancode.cli_test_utils import check_json_scan
from scancode.cli_test_utils import run_scan_click

from results_analyze.analyzer_plugin import validate_resource
from results_analyze.analyzer_plugin import NotAnalyzableResourceException


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

    def test_validate_resource_returns_true_if_all_attributes_are_present(self):
        data = {
            "licenses": [{"matched_text": "MIT License"}],
            "is_license_text": True,
            "is_legal": False,
        }
        test_resource = create_mock_resource(data)
        assert validate_resource(test_resource)

    def test_validate_resource_returns_false_if_no_licenses_are_matched(self):
        data = {
            "licenses": [],
            "is_license_text": False,
            "is_legal": False,
        }
        test_resource = create_mock_resource(data)
        assert not validate_resource(test_resource)

    def test_validate_resource_raise_exception_if_missing_is_legal(self):
        data = {
            "licenses": [{"matched_text": "MIT License"}],
            "is_license_text": True,
        }
        test_resource = create_mock_resource(data)
        try:
            validate_resource(test_resource)
            self.fail(msg="Exception not raised")
        except NotAnalyzableResourceException:
            pass

    def test_validate_resource_raise_exception_if_missing_is_license_text(self):
        data = {
            "licenses": [{"matched_text": "MIT License"}],
            "is_legal": False,
        }
        test_resource = create_mock_resource(data)
        try:
            validate_resource(test_resource)
            self.fail(msg="Exception not raised")
        except NotAnalyzableResourceException:
            pass

    def test_validate_resource_raise_exception_if_missing_license(self):
        data = {
            "is_legal": False,
            "is_license_text": True,
        }
        test_resource = create_mock_resource(data)
        try:
            validate_resource(test_resource)
            self.fail(msg="Exception not raised")
        except NotAnalyzableResourceException:
            pass

    def test_validate_resource_raise_exception_if_missing_all(self):
        data = {}
        test_resource = create_mock_resource(data)
        try:
            validate_resource(test_resource)
            self.fail(msg="Exception not raised")
        except NotAnalyzableResourceException:
            pass


def create_mock_resource(data):
    """
    Create a new resource subclass and return an instance of that subclass using the provided the
    data dictionary.
    """
    resource_attributes = build_attributes_defs(data)

    resource_class = attr.make_class(
        name='MockResource',
        attrs=resource_attributes,
        slots=True,
        bases=(Resource,))

    resource = resource_class(
        name= 'name',
        location = '/foo/bar',
        path = 'some/path/name',
        rid = 24,
        pid = 23,
        is_file = True,
        **data
    )

    return resource