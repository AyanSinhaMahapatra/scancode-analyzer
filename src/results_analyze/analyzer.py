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

from results_analyze.divide_cases import IMPERFECT_MATCH_COVERAGE_THR, \
    NEAR_PERFECT_MATCH_COVERAGE_THR, \
    LINES_THRESHOLD

# Whether to Use the NLP BERT Models
USE_LICENSE_CASE_BERT_MODEL = False
USE_FALSE_POSITIVE_BERT_MODEL = False


class LicenseMatchErrorResult:

    def __init__(self, location_region_number):

        self.location_region_number = location_region_number

        self.license_scan_analysis_result = None
        self.region_license_error_case = None
        self.region_license_error_sub_case = None

    def to_dict(self):
        """
        Return a dictionary with all the class attributes as key-value pairs.
        This is the dictionary which will be added as a result of the analysis, as a
        scancode 'resource_attribute'.

        :return license_match_error: dict
        """
        license_match_error_result = {
            "location_region_number": self.location_region_number,
            "license_scan_analysis_result": self.license_scan_analysis_result,
            "region_license_error_case": self.region_license_error_case,
            "region_license_error_sub_case": self.region_license_error_sub_case,
        }

        return license_match_error_result


def is_correct_detection(matched_licenses):
    """
    Return True if the matched licenses all points to a correct license detection.
    """
    matchers = (matched_license["matched_rule"]['matcher'] for matched_license in matched_licenses)
    return any(matcher in ('1-hash', '4-spdx-id') for matcher in matchers)


def is_match_coverage_less_than_threshold(matched_licenses, threshold):
    coverage_values = (matched_license["matched_rule"]['match_coverage']
                       for matched_license in matched_licenses)
    return any(coverage_value < threshold for coverage_value in coverage_values)


def calculate_query_coverage_coefficient(matched_license):
    matched_rule = matched_license["matched_rule"]
    score_coverage_relevance = (matched_rule["match_coverage"] * matched_rule["rule_relevance"]) / 100

    return score_coverage_relevance - matched_license["score"]


def is_extra_words(matched_licenses):
    match_query_coverage_diff_values = (calculate_query_coverage_coefficient(matched_license)
                                        for matched_license in matched_licenses)
    return any(match_query_coverage_diff_value > 0
             for match_query_coverage_diff_value in match_query_coverage_diff_values)


def is_false_positive(matched_licenses):
    match_rule_length_values = (matched_license["matched_rule"]['rule_length']
                                for matched_license in matched_licenses)
    match_is_license_tag_flags = (matched_license["matched_rule"]['is_license_tag']
                                  for matched_license in matched_licenses)
    return all((is_license_tag_flag and match_rule_length == 1)
        for is_license_tag_flag, match_rule_length in zip(
        match_is_license_tag_flags, match_rule_length_values))


def set_license_scan_analysis_result(license_scan_analysis_result, license_match_error_results):
    """
    Set the attribute license_scan_analysis_result on every LicenseMatchErrorResult object in the
    license_match_error_results list.
    """
    for license_match_error_result in license_match_error_results:
        license_match_error_result.license_scan_analysis_result = license_scan_analysis_result


def determine_license_scan_analysis_result_for_region(matched_licences, grouped_matches):

    is_correct_license_detection = is_correct_detection(matched_licences)

    if is_correct_license_detection:
        set_license_scan_analysis_result('correct-license-detection', grouped_matches)

    elif is_match_coverage_less_than_threshold(matched_licences, IMPERFECT_MATCH_COVERAGE_THR):
        set_license_scan_analysis_result('imperfect-match-coverage', grouped_matches)

    elif is_match_coverage_less_than_threshold(matched_licences, NEAR_PERFECT_MATCH_COVERAGE_THR):
        set_license_scan_analysis_result('near-perfect-match-coverage', grouped_matches)

    elif is_extra_words(matched_licences):
        set_license_scan_analysis_result('extra-words', grouped_matches)

    elif is_false_positive(matched_licences):
        if not USE_FALSE_POSITIVE_BERT_MODEL:
            set_license_scan_analysis_result('false-positive', grouped_matches)
        else:
            determine_false_positive_case_using_bert(matched_licences, grouped_matches)
    else:
        # Cases where Match Coverage is a perfect 100 for all matches
        set_license_scan_analysis_result('correct-license-detection', grouped_matches)
        is_correct_license_detection = True

    return is_correct_license_detection


def is_license_case(matched_licenses, license_case):
    match_is_license_case_flags = (matched_license["matched_rule"][license_case]
                                   for matched_license in matched_licenses)
    return any(match_is_license_case for match_is_license_case in match_is_license_case_flags)


def set_region_license_error_case(license_error_case, results_grouped_by_location):
    for result_object in results_grouped_by_location:
        result_object.region_license_error_case = license_error_case


def determine_license_error_case_by_region(matched_licences, results_grouped_by_location, is_license_text, is_legal):

    if is_license_text or is_legal or is_license_case(matched_licences, 'is_license_text'):
        set_region_license_error_case('text', results_grouped_by_location)

    elif is_license_case(matched_licences, 'is_license_notice'):
        set_region_license_error_case('notice', results_grouped_by_location)

    elif is_license_case(matched_licences, 'is_license_tag'):
        set_region_license_error_case('tag', results_grouped_by_location)

    elif is_license_case(matched_licences, 'is_license_reference'):
        set_region_license_error_case('reference', results_grouped_by_location)


def determine_license_error_case_using_bert(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def determine_false_positive_case_using_bert(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def determine_license_error_sub_case_by_region(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def analyze_region_for_license_scan_errors(matched_licences, results_grouped_by_location, is_license_text, is_legal):

    is_correct_license_detection = determine_license_scan_analysis_result_for_region(matched_licences,
                                                                                     results_grouped_by_location)

    if not is_correct_license_detection:

        if not USE_LICENSE_CASE_BERT_MODEL:
            determine_license_error_case_by_region(matched_licences, results_grouped_by_location,
                                                   is_license_text, is_legal)
        else:
            determine_license_error_case_using_bert(matched_licences, results_grouped_by_location)

        # TODO: Implement this function
        # determine_license_error_sub_case_by_region(matched_licences, results_grouped_by_location)


def group_license_matches_by_location_and_analyze(matched_licences, is_license_text, is_legal):
    """
    # TODO: Explain function and it's returns

    :param matched_licences:
    :param is_license_text:
    :param is_legal:
    :return:
    """
    license_detection_errors = []

    # Number of Matches in matched_licences
    num_matches_file = len(matched_licences)

    # Initialize Start/End counters for both lines numbers and their numerical Index values for the current match
    start_line_present_match = matched_licences[0]["start_line"]
    end_line_present_match = matched_licences[0]["end_line"]
    start_line_idx, end_line_idx = [0, 0]

    # Initialize present group number counter to 1
    present_group_number = 1

    # Initialize the first ErrorResult object and initialize it to be in region 1
    license_detection_error = LicenseMatchErrorResult(location_region_number=present_group_number)
    license_detection_errors.append(license_detection_error)

    # Loop through the Matches, starting from the second match
    for match in range(1, num_matches_file):

        # Get Start and End line for the current match
        start_line = matched_licences[match]["start_line"]
        end_line = matched_licences[match]["end_line"]

        # If present match falls in the present group
        if start_line <= (end_line_present_match + LINES_THRESHOLD):

            # Mark this match as under the present group and extend group end Index
            license_detection_error = LicenseMatchErrorResult(location_region_number=present_group_number)
            license_detection_errors.append(license_detection_error)
            end_line_idx = match

            # If `end_line` outside current line Boundaries, then Update Boundaries
            if end_line > end_line_present_match:
                end_line_present_match = end_line

        # If present match doesn't fall in the present group
        # i.e. the start_line is outside threshold
        elif start_line > (end_line_present_match + LINES_THRESHOLD):

            # Increase group number, and mark this match as in a new group
            present_group_number += 1
            license_detection_error = LicenseMatchErrorResult(location_region_number=present_group_number)
            license_detection_errors.append(license_detection_error)

            analyze_region_for_license_scan_errors(
                matched_licences=matched_licences[start_line_idx:end_line_idx+1],
                results_grouped_by_location=license_detection_errors[start_line_idx:end_line_idx+1],
                is_license_text=is_license_text,
                is_legal=is_legal)

            # Update Group Index to point to Current Group
            start_line_idx, end_line_idx = [match, match]

            # Update Line Boundaries
            end_line_present_match = end_line

    analyze_region_for_license_scan_errors(
        matched_licences=matched_licences[start_line_idx:end_line_idx+1],
        results_grouped_by_location=license_detection_errors[start_line_idx:end_line_idx+1],
        is_license_text=is_license_text,
        is_legal=is_legal)

    return license_detection_errors


def convert_list_of_result_class_to_list_of_dicts(list_results):
    license_match_error_result = []

    for result in list_results:
        license_match_error_result.append(result.to_dict())

    return license_match_error_result


def analyze_license_matches(matched_licences, is_license_text=False, is_legal=False):
    """
    Return a list of license detection errors.
    """
    if not matched_licences:
        return []

    results_grouped_by_location = group_license_matches_by_location_and_analyze(
        matched_licences, is_license_text, is_legal)

    analysis_results = convert_list_of_result_class_to_list_of_dicts(results_grouped_by_location)

    return analysis_results
