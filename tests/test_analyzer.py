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


class TestAnalyzer(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data/analyzer/')

    def test_analyzer_is_correct_detection_case_all_3_seq(self):

        test_file = self.get_test_loc('analyzer_is_correct_detection_case_all_3_seq.json')
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_all_1_hash(self):

        test_file = self.get_test_loc('analyzer_is_correct_detection_case_all_1_hash.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_mixed_123(self):

        test_file = self.get_test_loc('analyzer_is_correct_detection_case_mixed_123.json')
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_mixed_14(self):

        test_file = self.get_test_loc('analyzer_is_correct_detection_case_mixed_14.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_match_coverage_less_than_threshold_low(self):

        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_low.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_match_coverage_less_than_threshold(license_matches,
                                                              threshold=analyzer.IMPERFECT_MATCH_COVERAGE_THR)

    def test_analyzer_is_match_coverage_less_than_threshold_near_perfect(self):
        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_near_perfect.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_match_coverage_less_than_threshold(license_matches,
                                                              threshold=analyzer.NEAR_PERFECT_MATCH_COVERAGE_THR)
        assert not analyzer.is_match_coverage_less_than_threshold(license_matches,
                                                                  threshold=analyzer.IMPERFECT_MATCH_COVERAGE_THR)

    def test_analyzer_is_match_coverage_less_than_threshold_perfect(self):
        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_perfect.json')
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_match_coverage_less_than_threshold(license_matches,
                                                                  threshold=analyzer.NEAR_PERFECT_MATCH_COVERAGE_THR)

    def test_analyzer_calculate_query_coverage_coefficient_not_extra_words_correct_detection(self):

        test_file = self.get_test_loc('analyzer_calculate_query_coverage_coefficient_not_extra_words_correct_det.json')
        license_match = TestDataIO.load_json(test_file)

        assert analyzer.calculate_query_coverage_coefficient(license_match) == 0

    def test_analyzer_calculate_query_coverage_coefficient_not_extra_words_low_coverage(self):

        test_file = self.get_test_loc('analyzer_calculate_query_coverage_coefficient_not_extra_words_low_coverage.json')
        license_match = TestDataIO.load_json(test_file)

        assert analyzer.calculate_query_coverage_coefficient(license_match) == 0

    def test_analyzer_calculate_query_coverage_coefficient_is_extra_words(self):

        test_file = self.get_test_loc('analyzer_is_extra_words_true_one.json')
        license_matches = TestDataIO.load_json(test_file)

        for license_match in license_matches:
            assert analyzer.calculate_query_coverage_coefficient(license_match) > 0

    def test_analyzer_is_extra_words_true_one(self):
        test_file = self.get_test_loc('analyzer_is_extra_words_true_one.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_extra_words(license_matches)

    def test_analyzer_is_extra_words_false(self):
        test_file = self.get_test_loc('analyzer_is_correct_detection_case_all_3_seq.json')
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_extra_words(license_matches)

    def test_analyzer_is_false_positive_true(self):
        test_file = self.get_test_loc('analyzer_is_false_positive_true.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_false_positive(license_matches)

    def test_analyzer_is_false_positive_false_tag(self):
        test_file = self.get_test_loc('analyzer_is_false_positive_false_tag.json')
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_false_positive(license_matches)

    def test_analyzer_set_license_scan_analysis_result(self):

        license_match_error_results = analyzer.initialize_results(number_of_matches=5, present_group_number=0)
        analyzer.set_license_scan_analysis_result("correct-license-detection", license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "correct-license-detection"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_correct_hash(self):

        test_file = self.get_test_loc('analyzer_is_correct_detection_case_all_1_hash.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert analyzer.determine_license_scan_analysis_result_for_region(license_matches, license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "correct-license-detection"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_correct_aho(self):

        test_file = self.get_test_loc('analyzer_determine_license_scan_analysis_result_correct_aho.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert analyzer.determine_license_scan_analysis_result_for_region(license_matches, license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "correct-license-detection"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_incorrect_low_coverage(self):

        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_low.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert not analyzer.determine_license_scan_analysis_result_for_region(license_matches,
                                                                              license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "imperfect-match-coverage"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_incorrect_near_perfect_coverage(self):

        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_near_perfect.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert not analyzer.determine_license_scan_analysis_result_for_region(license_matches,
                                                                              license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "near-perfect-match-coverage"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_incorrect_extra_words(self):

        test_file = self.get_test_loc('analyzer_is_extra_words_true.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert not analyzer.determine_license_scan_analysis_result_for_region(license_matches,
                                                                              license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "extra-words"

    def test_analyzer_determine_license_scan_analysis_result_for_region_case_incorrect_false_positives(self):

        test_file = self.get_test_loc('analyzer_is_false_positive_true.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert not analyzer.determine_license_scan_analysis_result_for_region(license_matches,
                                                                              license_match_error_results)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.license_scan_analysis_result == "false-positive"

    def test_analyzer_is_license_case_mixed_text(self):
        test_file = self.get_test_loc('analyzer_is_license_case_mix_text.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_text")

    def test_analyzer_is_license_case_all_notice(self):
        test_file = self.get_test_loc('analyzer_is_license_case_all_notice.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_notice")

    def test_analyzer_is_license_case_mixed_notice(self):

        test_file = self.get_test_loc('analyzer_is_match_coverage_less_than_threshold_low.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_notice")

    def test_analyzer_is_license_case_mixed_tag(self):
        test_file = self.get_test_loc('analyzer_is_license_case_mix_tag.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_tag")

    def test_analyzer_is_license_case_all_ref(self):
        test_file = self.get_test_loc('analyzer_is_license_case_all_reference.json')
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_reference")

    def test_analyzer_set_region_license_error_case(self):

        results_group = analyzer.initialize_results(number_of_matches=5, present_group_number=0)
        analyzer.set_region_license_error_case("is_license_notice", results_group)

        for result in results_group:
            assert result.region_license_error_case == "is_license_notice"

    def test_analyzer_determine_license_error_case_by_rule_type_case_notice(self):

        test_file = self.get_test_loc('analyzer_group_matches_notice_reference_fragments.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.initialize_results(number_of_matches=len(license_matches),
                                                                  present_group_number=0)

        assert not analyzer.determine_license_error_case_by_rule_type(license_matches, license_match_error_results,
                                                                      is_license_text=False, is_legal=False)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.region_license_error_case == "notice"

    def test_analyzer_initialize_results(self):

        results = analyzer.initialize_results(number_of_matches=7, present_group_number=0)

        for result in results:
            assert result.license_scan_analysis_result is None
            assert result.region_license_error_case is None
            assert result.region_license_error_sub_case is None
            assert result.location_region_number == 1
        assert 7 == len(results)

    def test_analyzer_analyze_region_for_license_scan_errors(self):

        test_file = self.get_test_loc('analyzer_group_matches_notice_reference_fragments.json')
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_results = analyzer.analyze_region_for_license_scan_errors(license_matches, group_number=0,
                                                                                is_license_text=False, is_legal=False)

        for license_match_error_result in license_match_error_results:
            assert license_match_error_result.region_license_error_case == "notice"

    def test_analyzer_group_matches_boundary_case_lines_threshold(self):

        test_file = self.get_test_loc('analyzer_group_matches_boundary_case_lines_threshold.json')
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(ungrouped_matches, analyzer.LINES_THRESHOLD)

        assert len(list(grouped_matches)) == 2

    # TODO: don't group false positives together
    def test_analyzer_group_matches_multiple_false_positives(self):

        test_file = self.get_test_loc('analyzer_group_matches_multiple_false_positives.json')
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(ungrouped_matches, analyzer.LINES_THRESHOLD)

        assert len(list(grouped_matches)) == 3

    def test_analyzer_group_matches_notice_reference_fragments(self):

        test_file = self.get_test_loc('analyzer_group_matches_notice_reference_fragments.json')
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(ungrouped_matches, analyzer.LINES_THRESHOLD)

        assert len(list(grouped_matches)) == 2

    def test_analyzer_convert_list_of_result_class_to_list_of_dicts(self):
        results_group = analyzer.initialize_results(number_of_matches=5, present_group_number=0)
        result_dicts = analyzer.convert_list_of_result_class_to_list_of_dicts(results_group)

        for result in result_dicts:
            assert type(result) == dict
            assert result["location_region_number"] == 1


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
