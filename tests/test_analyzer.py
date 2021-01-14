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
    test_data_dir = os.path.join(os.path.dirname(__file__), "data/analyzer/")

    def test_analyzer_is_correct_detection_case_all_3_seq(self):

        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_all_3_seq.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_all_1_hash(self):

        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_all_1_hash.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_mixed_123(self):

        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_mixed_123.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_correct_detection_case_mixed_14(self):

        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_mixed_14.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_correct_detection(license_matches)

    def test_analyzer_is_match_coverage_less_than_threshold_low(self):

        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_low.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_match_coverage_less_than_threshold(
            license_matches, threshold=analyzer.IMPERFECT_MATCH_COVERAGE_THR
        )

    def test_analyzer_is_match_coverage_less_than_threshold_near_perfect(self):
        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_near_perfect.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_match_coverage_less_than_threshold(
            license_matches, threshold=analyzer.NEAR_PERFECT_MATCH_COVERAGE_THR
        )
        assert not analyzer.is_match_coverage_less_than_threshold(
            license_matches, threshold=analyzer.IMPERFECT_MATCH_COVERAGE_THR
        )

    def test_analyzer_is_match_coverage_less_than_threshold_perfect(self):
        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_perfect.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_match_coverage_less_than_threshold(
            license_matches, threshold=analyzer.NEAR_PERFECT_MATCH_COVERAGE_THR
        )

    def test_analyzer_query_coverage_coefficient_not_extra_words_correct_detection(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_calculate_query_coverage_coefficient_not_extra_words_correct_det.json"
        )
        license_match = TestDataIO.load_json(test_file)

        assert analyzer.calculate_query_coverage_coefficient(license_match) == 0

    def test_analyzer_calculate_query_coverage_coefficient_not_extra_words_low_coverage(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_calculate_query_coverage_coefficient_not_extra_words_low_coverage.json"
        )
        license_match = TestDataIO.load_json(test_file)

        assert analyzer.calculate_query_coverage_coefficient(license_match) == 0

    def test_analyzer_calculate_query_coverage_coefficient_is_extra_words(self):

        test_file = self.get_test_loc("analyzer_is_extra_words_true_one.json")
        license_matches = TestDataIO.load_json(test_file)

        for license_match in license_matches:
            assert analyzer.calculate_query_coverage_coefficient(license_match) > 0

    def test_analyzer_is_extra_words_true_one(self):
        test_file = self.get_test_loc("analyzer_is_extra_words_true_one.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_extra_words(license_matches)

    def test_analyzer_is_extra_words_false(self):
        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_all_3_seq.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_extra_words(license_matches)

    def test_analyzer_is_false_positive_true(self):
        test_file = self.get_test_loc("analyzer_is_false_positive_true.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_false_positive(license_matches)

    def test_analyzer_is_false_positive_false_tag(self):
        test_file = self.get_test_loc("analyzer_is_false_positive_false_tag.json")
        license_matches = TestDataIO.load_json(test_file)

        assert not analyzer.is_false_positive(license_matches)

    def test_analyzer_determine_analysis_result_for_region_case_correct_hash(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_is_correct_detection_case_all_1_hash.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert (
            license_match_error_result.license_scan_analysis_result
            == "correct-license-detection"
        )

    def test_analyzer_determine_analysis_result_for_region_case_correct_aho(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_determine_license_scan_analysis_result_correct_aho.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert (
            license_match_error_result.license_scan_analysis_result
            == "correct-license-detection"
        )

    def test_analyzer_determine_analysis_result_for_region_case_incorrect_low_coverage(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_low.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert not analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert (
            license_match_error_result.license_scan_analysis_result
            == "imperfect-match-coverage"
        )

    def test_analyzer_analysis_result_for_region_case_incorrect_near_perfect_coverage(
        self,
    ):

        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_near_perfect.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert not analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert (
            license_match_error_result.license_scan_analysis_result
            == "near-perfect-match-coverage"
        )

    def test_analyzer_analysis_result_for_region_case_incorrect_extra_words(
        self,
    ):

        test_file = self.get_test_loc("analyzer_is_extra_words_true.json")
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert not analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert license_match_error_result.license_scan_analysis_result == "extra-words"

    def test_analyzer_analysis_result_for_region_case_incorrect_false_positives(
        self,
    ):

        test_file = self.get_test_loc("analyzer_is_false_positive_true.json")
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert not analyzer.determine_license_scan_analysis_result_for_region(
            license_matches, license_match_error_result
        )

        assert (
            license_match_error_result.license_scan_analysis_result == "false-positive"
        )

    def test_analyzer_is_license_case_mixed_text(self):
        test_file = self.get_test_loc("analyzer_is_license_case_mix_text.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_text")

    def test_analyzer_is_license_case_all_notice(self):
        test_file = self.get_test_loc("analyzer_is_license_case_all_notice.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_notice")

    def test_analyzer_is_license_case_mixed_notice(self):

        test_file = self.get_test_loc(
            "analyzer_is_match_coverage_less_than_threshold_low.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_notice")

    def test_analyzer_is_license_case_mixed_tag(self):
        test_file = self.get_test_loc("analyzer_is_license_case_mix_tag.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_tag")

    def test_analyzer_is_license_case_all_ref(self):
        test_file = self.get_test_loc("analyzer_is_license_case_all_reference.json")
        license_matches = TestDataIO.load_json(test_file)

        assert analyzer.is_license_case(license_matches, "is_license_reference")

    def test_analyzer_determine_license_error_case_by_rule_type_case_notice(self):

        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.AnalysisResult()

        assert not analyzer.determine_license_error_case_by_rule_type(
            license_matches,
            license_match_error_result,
            is_license_text=False,
            is_legal=False,
        )

        assert license_match_error_result.region_license_error_case == "notice"

    def test_analyzer_initialize_results(self):

        result = analyzer.AnalysisResult()

        assert result.license_scan_analysis_result is None
        assert result.region_license_error_case is None
        assert result.region_license_error_sub_case is None

    def test_merge_string_without_overlap(self):
        test_file = self.get_test_loc("merge_strings_test_strings.json")
        strings = TestDataIO.load_json(test_file)

        merged_string = analyzer.merge_string_without_overlap(
            strings["merge_without_overlap_string_1"],
            strings["merge_without_overlap_string_2"]
        )

        assert merged_string == strings["merge_without_overlap"]

    def test_merge_string_with_overlap(self):
        test_file = self.get_test_loc("merge_strings_test_strings.json")
        strings = TestDataIO.load_json(test_file)

        merged_string = analyzer.merge_string_with_overlap(
            strings["merge_with_overlap_string_1"],
            strings["merge_with_overlap_string_2"]
        )

        assert merged_string == strings["merge_with_overlap"]

    def test_get_start_end_line(self):
        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments_group_1.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        start_line, end_line = analyzer.get_start_end_line(license_matches)

        assert start_line == 14
        assert end_line == 34

    def test_predict_license_key(self):
        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments_group_1.json"
        )
        license_matches = TestDataIO.load_json(test_file)
        expectation_file = self.get_test_loc("consolidated_match_expected.json")
        expected_prediction = TestDataIO.load_json(expectation_file)

        prediction_key = analyzer.predict_license_key(license_matches)
        assert prediction_key == expected_prediction["key"]

    def test_get_license_match_from_region(self):
        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments_group_1.json"
        )
        license_matches = TestDataIO.load_json(test_file)
        expectation_file = self.get_test_loc("consolidated_match_expected.json")
        expected_match = TestDataIO.load_json(expectation_file)

        result_match = analyzer.get_license_match_from_region(
            license_matches, "imperfect-match-coverage"
        )

        assert result_match == expected_match

    def test_consolidate_matches_in_one_region(self):
        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments_group_1.json"
        )
        license_matches = TestDataIO.load_json(test_file)
        expectation_file = self.get_test_loc("consolidated_match_expected.json")
        expected_match = TestDataIO.load_json(expectation_file)

        result_match = analyzer.consolidate_matches_in_one_region(license_matches)
        assert result_match == expected_match

    def test_analyzer_analyze_region_for_license_scan_errors(self):

        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments.json"
        )
        license_matches = TestDataIO.load_json(test_file)

        license_match_error_result = analyzer.analyze_region_for_license_scan_errors(
            license_matches, is_license_text=False, is_legal=False
        )

        assert license_match_error_result.region_license_error_case == "notice"

    def test_analyzer_group_matches_boundary_case_lines_threshold(self):

        test_file = self.get_test_loc(
            "analyzer_group_matches_boundary_case_lines_threshold.json"
        )
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(
            ungrouped_matches, analyzer.LINES_THRESHOLD
        )

        assert len(list(grouped_matches)) == 2

    # TODO: don't group false positives together
    def test_analyzer_group_matches_multiple_false_positives(self):

        test_file = self.get_test_loc(
            "analyzer_group_matches_multiple_false_positives.json"
        )
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(
            ungrouped_matches, analyzer.LINES_THRESHOLD
        )

        assert len(list(grouped_matches)) == 3

    def test_analyzer_group_matches_notice_reference_fragments(self):

        test_file = self.get_test_loc(
            "analyzer_group_matches_notice_reference_fragments.json"
        )
        ungrouped_matches = TestDataIO.load_json(test_file)

        grouped_matches = analyzer.group_matches(
            ungrouped_matches, analyzer.LINES_THRESHOLD
        )

        assert len(list(grouped_matches)) == 2


class TestLicenseMatchErrorResult(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), "data/analyzer/")

    def test_analyze_license_matches_return_empty_list_with_none_matches(self):
        analysis_results = analyzer.analyze_license_matches(None)
        assert [] == analysis_results

    def test_analyze_license_matches_return_empty_list_with_empty_matches(self):
        analysis_results = analyzer.analyze_license_matches([])
        assert [] == analysis_results

    def test_group_license_matches_by_location_and_analyze(self):

        # TODO: Add Explanation for all creation of test Files from scancode scan results
        test_file = self.get_test_loc("group_matches_by_location_analyze.json")
        expected_file = self.get_test_loc(
            "group_matches_by_location_analyze_result.json"
        )

        file_scan_result = TestDataIO.load_json(test_file)
        expected = TestDataIO.load_json(expected_file)

        matched_licences = file_scan_result["licenses"]
        is_license_text = file_scan_result["is_license_text"]
        is_legal = file_scan_result["is_legal"]

        analysis_results = analyzer.analyze_license_matches(
            matched_licences=matched_licences,
            is_license_text=is_license_text,
            is_legal=is_legal,
        )

        assert expected == analysis_results
