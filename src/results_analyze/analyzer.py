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

# All values of match_coverage less than this value are taken as `near-perfect-match-coverage` cases
NEAR_PERFECT_MATCH_COVERAGE_THR = 100

# Values of match_coverage less than this are taken as `imperfect-match-coverage` cases
IMPERFECT_MATCH_COVERAGE_THR = 95

# How many Lines in between has to be present for two matches being of a different group
# (i.e. and therefore, different rule)
LINES_THRESHOLD = 4

# Whether to Use the NLP BERT Models
USE_LICENSE_CASE_BERT_MODEL = False
USE_FALSE_POSITIVE_BERT_MODEL = False


class LicenseMatchErrorResult:

    def __init__(self, location_region_number):
        """
        Initializes a LicenseMatchErrorResult object for one license match, i.e. as a file-region
        can have multiple license matches, license detection errors for a file/region would have
        a list of these objects.

        :param location_region_number: int
            Region number in the file, which this match is in.
        """
        self.location_region_number = location_region_number

        self.license_scan_analysis_result = None
        self.region_license_error_case = None
        self.region_license_error_sub_case = None

    def to_dict(self):
        """
        Return a dictionary with all the class attributes as key-value pairs.
        This is the dictionary which will be added as a result of the analysis, in a list,
        as a scancode 'resource_attribute'.

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
    Return True if all the license matches in a file-region are correct license detections,
    as they are either SPDX license tags, or the file content has a exact match with a license hash.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
    matchers = (matched_license["matched_rule"]['matcher'] for matched_license in matched_licenses)
    return all(matcher in ('1-hash', '4-spdx-id') for matcher in matchers)


def is_match_coverage_less_than_threshold(matched_licenses, threshold):
    """
    Returns True if any of the license matches in a file-region has a `match_coverage`
    value below the threshold.

    :param matched_licenses: list
        List of license matches in a file-region.
    :param threshold: int
        A `match_coverage` threshold value in between 0-100
    """
    coverage_values = (matched_license["matched_rule"]['match_coverage']
                       for matched_license in matched_licenses)
    return any(coverage_value < threshold for coverage_value in coverage_values)


def calculate_query_coverage_coefficient(matched_license):
    """
    Calculates a `query_coverage_coefficient` value for that match. For a match:
    1. If this value is 0, i.e. `score` == `match_coverage` * `rule_Relevance`, then there are no
       extra words in that license match.
    2. If this value is a positive number, i.e. `score` != `match_coverage` * `rule_Relevance`,
       then there are extra words in that match.

    :param matched_license: dict
        A license match dictionary containing all the match attributes.
    """
    matched_rule = matched_license["matched_rule"]
    score_coverage_relevance = (matched_rule["match_coverage"] * matched_rule["rule_relevance"]) / 100

    return score_coverage_relevance - matched_license["score"]


def is_extra_words(matched_licenses):
    """
    Return True if any of the license matches in a file-region has extra words. Having extra words
    means contains a perfect match with a license/rule, but there are some extra words in addition
    to the matched text.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
    match_query_coverage_diff_values = (calculate_query_coverage_coefficient(matched_license)
                                        for matched_license in matched_licenses)
    return any(match_query_coverage_diff_value > 0
               for match_query_coverage_diff_value in match_query_coverage_diff_values)


def is_false_positive(matched_licenses):
    """
    Return True if all of the license matches in a file-region are false positives.
    False Positive occurs when other text/code is falsely matched to a license rule, because
    it matches with a one-word license rule with it's `is_license_tag` value as True.
    Note: Usually if it's a false positive, there's only one match in that region.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
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

    :param license_scan_analysis_result: string
        Has one of the 5 possible values of LicenseMatchErrorResult.license_scan_analysis_result
    :param license_match_error_results: list
        List of LicenseMatchErrorResult objects, for a file-region.
    :return:
    """
    for license_match_error_result in license_match_error_results:
        license_match_error_result.license_scan_analysis_result = license_scan_analysis_result


def determine_license_scan_analysis_result_for_region(matched_licences, analysis_results):
    """
    Analyse license matches from a file-region, and determine if the license detection in
    that file region (i.e. group of matches coming from one location in a file) is correct
    or it is wrong/partially-correct/there's scope of improvement. Group these incorrect matches
    by analysing their attributes.

    :param matched_licences: list
        List of matched licenses in a file-region.
    :param analysis_results:
        List of LicenseMatchErrorResult objects, one for each match in the list of matched_licenses
    """
    # Case where all matches have `matcher` as `1-hash` or `4-spdx-id`
    is_correct_license_detection = is_correct_detection(matched_licences)
    if is_correct_license_detection:
        set_license_scan_analysis_result('correct-license-detection', analysis_results)

    # Case where at least one of the matches have `match_coverage` below IMPERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(matched_licences, IMPERFECT_MATCH_COVERAGE_THR):
        set_license_scan_analysis_result('imperfect-match-coverage', analysis_results)

    # Case where at least one of the matches have `match_coverage` below NEAR_PERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(matched_licences, NEAR_PERFECT_MATCH_COVERAGE_THR):
        set_license_scan_analysis_result('near-perfect-match-coverage', analysis_results)

    # Case where at least one of the match have extra words
    elif is_extra_words(matched_licences):
        set_license_scan_analysis_result('extra-words', analysis_results)

    # Case where the match is a false positive
    elif is_false_positive(matched_licences):
        if not USE_FALSE_POSITIVE_BERT_MODEL:
            set_license_scan_analysis_result('false-positive', analysis_results)
        else:
            determine_false_positive_case_using_bert(matched_licences, analysis_results)

    # Cases where Match Coverage is a perfect 100 for all matches
    else:
        set_license_scan_analysis_result('correct-license-detection', analysis_results)
        is_correct_license_detection = True

    return is_correct_license_detection


def is_license_case(matched_licenses, license_case):
    """
    Get the type of license_match_case for a group of license matches in a file-region.

    :param matched_licenses: list
        List of matched licenses in a file-region
    :param license_case: string
        One of the 4 boolean flag attributes of a match, i.e. is it text/notice/tag/ref
    """
    match_is_license_case_flags = (matched_license["matched_rule"][license_case]
                                   for matched_license in matched_licenses)
    return any(match_is_license_case for match_is_license_case in match_is_license_case_flags)


def set_region_license_error_case(license_error_case, results_grouped_by_location):
    """
    Set the attribute region_license_error_case on every LicenseMatchErrorResult object in the
    results_grouped_by_location list.

    :param license_error_case: string
        One of the 4 boolean flag attributes of a match, i.e. is it text/notice/tag/ref
    :param results_grouped_by_location: list
        List of LicenseMatchErrorResult objects, for a file-region.
    """
    for result_object in results_grouped_by_location:
        result_object.region_license_error_case = license_error_case


def determine_license_error_case_by_rule_type(matched_licences, results_grouped_by_location, is_license_text, is_legal):
    """
    For a group of matches (with some issue) in a file-region, divide them into groups according
    to their license rule type.

    :param matched_licences: list
        A list of all matches in a file-region.
    :param results_grouped_by_location:
        List of LicenseMatchErrorResult objects, one for each match in the list of matched_licenses
    :param is_license_text: bool
    :param is_legal: bool
    """
    # Case where at least one of the matches is matched to a `text` rule.
    if is_license_text or is_legal or is_license_case(matched_licences, 'is_license_text'):
        set_region_license_error_case('text', results_grouped_by_location)

    # Case where at least one of the matches is matched to a `notice` rule.
    elif is_license_case(matched_licences, 'is_license_notice'):
        set_region_license_error_case('notice', results_grouped_by_location)

    # Case where at least one of the matches is matched to a `tag` rule.
    elif is_license_case(matched_licences, 'is_license_tag'):
        set_region_license_error_case('tag', results_grouped_by_location)

    # Case where at least one of the matches is matched to a `reference` rule.
    elif is_license_case(matched_licences, 'is_license_reference'):
        set_region_license_error_case('reference', results_grouped_by_location)


def determine_license_error_case_by_rule_type_using_bert(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def determine_false_positive_case_using_bert(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def determine_license_error_sub_case_rule_type(matched_licences, results_grouped_by_location):
    raise NotImplementedError


def initialize_results(number_of_matches, present_group_number):
    """
    For a group of matches in a file-region, generate a LicenseMatchErrorResult object for each of
    those matches.

    :param number_of_matches: int
    :param present_group_number: int
    :return license_detection_errors: list
        List of n LicenseMatchErrorResult objects, where n -> number_of_matches.
    """

    license_detection_errors = []

    for result in range(number_of_matches):
        license_detection_error = LicenseMatchErrorResult(location_region_number=present_group_number+1)
        license_detection_errors.append(license_detection_error)

    return license_detection_errors


def analyze_region_for_license_scan_errors(matched_licences, group_number, is_license_text, is_legal):
    """
    On a group of license matches (grouped on the basis of location in file), perform steps of
    analysis to determine if the license match is correct or if it has any issues. In case of issues,
    divide the issues into groups of commonly detected issues.

    :param matched_licences: list
        A list of all matches in a file-region.
    :param group_number: int
        The order of this file-region in file. Starts from 1.
    :param is_license_text: bool
    :param is_legal: bool
    :returns results_grouped_by_location:
        List of LicenseMatchErrorResult objects, one for each match in the list of matched_licenses
    """
    results_grouped_by_location = initialize_results(number_of_matches=len(matched_licences),
                                                     present_group_number=group_number)

    is_correct_license_detection = determine_license_scan_analysis_result_for_region(matched_licences,
                                                                                     results_grouped_by_location)

    # If one of the matches in the file-region has issues, group it into further sub-groups
    if not is_correct_license_detection:

        if not USE_LICENSE_CASE_BERT_MODEL:
            determine_license_error_case_by_rule_type(matched_licences, results_grouped_by_location,
                                                      is_license_text, is_legal)
        else:
            determine_license_error_case_by_rule_type_using_bert(matched_licences, results_grouped_by_location)

        # TODO: Implement this function
        # determine_license_error_sub_case_rule_type(matched_licences, results_grouped_by_location)

    return results_grouped_by_location


def group_matches(matches, lines_threshold=LINES_THRESHOLD):
    """
    Given a list of `matches` yield lists of grouped matches together where each
    group is less than `lines_threshold` apart.
    Each item in `matches` is a ScanCode matched license using the structure
    that is found in the JSON scan results.

    :param matches: list
        list of dicts, one for each license match in a file.
    :param lines_threshold: int
        The maximum space that can exist between two matches for them to be considered in the same
        file-region.
    :returns: list generator
        A list of groups, where each group is a list of matches.
    """
    group = []
    for match in matches:
        if not group:
            group.append(match)
            continue
        previous = group[-1]
        is_in_group = (match["start_line"] <= previous["end_line"] + lines_threshold)
        if is_in_group:
            group.append(match)
            continue
        else:
            yield group
            group = [match]

    yield group


def analyze_matches(grouped_matches, is_license_text, is_legal):
    """
    Analyze a list of groups of matches, one group at a time, for license detection errors.

    :param grouped_matches: list generator
        A list of groups, where each group is a list of matches.
    :param is_license_text: bool
    :param is_legal: bool
    :returns: list generator
        A list of LicenseMatchErrorResult objects one for each match in the file.
    """
    for group_number, group in enumerate(grouped_matches):
        for analysis in analyze_region_for_license_scan_errors(matched_licences=group, group_number=group_number,
                                                               is_license_text=is_license_text, is_legal=is_legal):
            yield analysis


def convert_list_of_result_class_to_list_of_dicts(list_results):
    """
    Converts a list of `LicenseMatchErrorResult` objects to a list of dictionaries, to be added as a
    scancode `resource_attribute`.

    :param list_results: list
        A list of `LicenseMatchErrorResult` objects
    :return license_match_error_result:
        A list of dictionaries having the result of License Scan Analysis
    """
    license_match_error_result = []

    # Convert each `LicenseMatchErrorResult` object to a dictionary and add to the list of dicts
    for result in list_results:
        license_match_error_result.append(result.to_dict())

    return license_match_error_result


def analyze_license_matches(matched_licences, is_license_text=False, is_legal=False):
    """
    This function takes as input all the license matches in a file, and returns the results
    of the license detection error analysis, for each match in a file.

    :param matched_licences: list
        A list of all matches in a file.
    :param is_license_text: bool
        A Scancode `resource_attribute` for the file. True if more than 90% of a file has license
        text.
    :param is_legal: bool
        A Scancode `resource_attribute` for the file. True if the file has a common legal name.
    :returns analysis_results: list
        A list of dicts, with keys-values corresponding to their LicenseMatchErrorResult objects, for each
        license match in the file, having the analysis results on the file's license detections.
    """
    if not matched_licences:
        return []

    # Partitions the license matches into `file-regions` which are group of matches present in one location of a file,
    # with some overlap, or the difference between their end and start line numbers is less than a threshold.
    grouped_matches = group_matches(matched_licences)

    # Then for each of these `file-regions`, all of their matches are passed on to functions
    # analysing those matches together, for license detection errors
    results_grouped_by_location = analyze_matches(grouped_matches, is_license_text, is_legal)

    # Convert the list of LicenseMatchErrorResult objects to list of dicts, in the format it has to be added to
    # each resource object in scancode results
    analysis_results = convert_list_of_result_class_to_list_of_dicts(results_grouped_by_location)

    return analysis_results
