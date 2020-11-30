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

from load_test_data import TestDataIO

from results_analyze import analyzer


class TestLicenseMatchErrorResult(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data/analyzer/')

    def test_analyze_license_matches_return_empty_list_with_none_matches(self):
        analysis_results = analyzer.analyze_license_matches(None)
        assert [] == analysis_results

    def test_analyze_license_matches_return_empty_list_with_empty_matches(self):
        analysis_results = analyzer.analyze_license_matches([])
        assert [] == analysis_results

    def test_analyze_license_matches_can_analyze_simple_license_match(self):
        test_matches = [
            {
              "key": "gpl-1.0-plus",
              "score": 73.33,
              "name": "GNU General Public License 1.0 or later",
              "short_name": "GPL 1.0 or later",
              "category": "Copyleft",
              "is_exception": False,
              "owner": "Free Software Foundation (FSF)",
              "homepage_url": "http://www.gnu.org/licenses/old-licenses/gpl-1.0-standalone.html",
              "text_url": "http://www.gnu.org/licenses/old-licenses/gpl-1.0-standalone.html",
              "reference_url": "https://enterprise.dejacode.com/urn/urn:dje:license:gpl-1.0-plus",
              "spdx_license_key": "GPL-1.0-or-later",
              "spdx_url": "https://spdx.org/licenses/GPL-1.0-or-later",
              "start_line": 4,
              "end_line": 4,
              "matched_rule": {
                "identifier": "gpl-1.0-plus_43.RULE",
                "license_expression": "gpl-1.0-plus",
                "licenses": [
                  "gpl-1.0-plus"
                ],
                "is_license_text": False,
                "is_license_notice": True,
                "is_license_reference": False,
                "is_license_tag": False,
                "matcher": "3-seq",
                "rule_length": 15,
                "matched_length": 11,
                "match_coverage": 73.33,
                "rule_relevance": 100.0
              },
              "matched_text": "# This is free software, licensed under the GNU General Public License v2."
            },
        ]

        expected = [
            {'location_region_number': 1,
             'license_scan_analysis_result': 'imperfect-match-coverage',
             'region_license_error_case': 'notice',
             'region_license_error_sub_case': None},
        ]

        result = analyzer.analyze_license_matches(matched_licences=test_matches)
        assert result == expected

    def test_analyze_license_matches_can_analyze_simple_license_match_2(self):
        test_matches = [
            {
              "key": "gpl-1.0-plus",
              "score": 73.33,
              "name": "GNU General Public License 1.0 or later",
              "short_name": "GPL 1.0 or later",
              "category": "Copyleft",
              "is_exception": False,
              "owner": "Free Software Foundation (FSF)",
              "homepage_url": "http://www.gnu.org/licenses/old-licenses/gpl-1.0-standalone.html",
              "text_url": "http://www.gnu.org/licenses/old-licenses/gpl-1.0-standalone.html",
              "reference_url": "https://enterprise.dejacode.com/urn/urn:dje:license:gpl-1.0-plus",
              "spdx_license_key": "GPL-1.0-or-later",
              "spdx_url": "https://spdx.org/licenses/GPL-1.0-or-later",
              "start_line": 4,
              "end_line": 4,
              "matched_rule": {
                "identifier": "gpl-1.0-plus_43.RULE",
                "license_expression": "gpl-1.0-plus",
                "licenses": [
                  "gpl-1.0-plus"
                ],
                "is_license_text": True,
                "is_license_notice": False,
                "is_license_reference": False,
                "is_license_tag": False,
                "matcher": "3-seq",
                "rule_length": 15,
                "matched_length": 11,
                "match_coverage": 73.33,
                "rule_relevance": 100.0
              },
              "matched_text": "# This is free software, licensed under the GNU General Public License v2."
            },
        ]

        expected = [
            {'location_region_number': 1,
             'license_scan_analysis_result': 'imperfect-match-coverage',
             'region_license_error_case': 'text',
             'region_license_error_sub_case': None},
        ]

        result = analyzer.analyze_license_matches(matched_licences=test_matches)
        assert result == expected

    def test_group_license_matches_by_location_and_analyze(self):

        # TODO: Add Explanation for all creation of test Files from scancode scan results
        test_file = self.get_test_loc('group_matches_by_location_analyze.json')
        expected_file = self.get_test_loc('group_matches_by_location_analyze_result.json')

        file_scan_result = TestDataIO.load_json(test_file)
        expected = TestDataIO.load_json(expected_file)

        matched_licences = file_scan_result["licenses"]
        is_license_text = file_scan_result["is_license_text"]
        is_legal = file_scan_result["is_legal"]

        analysis_results = analyzer.analyze_license_matches(matched_licences=matched_licences,
                                                            is_license_text=is_license_text, is_legal=is_legal)

        assert expected == analysis_results
