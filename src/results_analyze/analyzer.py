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

ERROR_CASES_VERSION = 0.1

# Description Fields for all possible values of `license_scan_analysis_result`
DESCRIPTIONS_ANALYSIS_RESULT = {
    "correct-license-detection": "The license detection is correct",
    "imperfect-match-coverage": "The license detection is incorrect, a large variation "
    "is present from the matched rule(s) and is matched to "
    "only one part of the whole text",
    "near-perfect-match-coverage": "The license detection is incorrect but the match "
    "is almost correct, only a small percentage of the "
    "text is not matched",
    "extra-words": "A license rule from the scancode rules matches completely with "
    "a part of the text, but there's some extra words which aren't "
    "there in the rule",
    "false-positives": "A piece of code/text is incorrectly detected as a license",
}

# Description Fields for all possible values of `region_license_error_case`
DESCRIPTIONS_ERROR_CASE = {
    "text": "The entire/partial license text i.e. the actual terms and conditions of "
    "the license and it's implications is present in the matched text",
    "notice": "A notice referencing the license name and some terms/implications are "
    "present in the matched text",
    "tag": "Only a reference to a license in an existing structure is present in the "
    "matched text",
    "reference": "A reference to a license in the form of a local file/online link",
}

# Description Fields for all possible values of `region_license_error_sub_case`
DESCRIPTIONS_ERROR_SUB_CASE = {
    # `text` sub-cases
    "text-legal-lic-files": "the matched text is present in a file whose name is a "
    "known legal filename",
    "text-non-legal-lic-files": "the matched text isn't present in a file having a "
    "known legal filename",
    "text-lic-text-fragments": "only parts of a larger license text is detected",
    # `notice` sub-cases
    "notice-and-or-except-notice": "a notice which notifies multiple licenses, "
    "as exceptions, as a choice between, or as together",
    "notice-single-key-notice": "a notice that notifies a single license",
    # `tag` sub-cases
    "tag-tag-coverage": "a part of a license tag is detected",
    "tag-other-tag-structures": "a new structure of tags are detected with scope for "
    "being handled differently",
    "tag-false-positives": "A piece of code/text is incorrectly detected as a license",
    # `reference` sub-cases
    "reference-lead-in-refs": "lead-ins to known license references are detected",
    "reference-low-coverage-refs": "license references with a incomplete match",
    "reference-unknown-refs": "license references with unknown licenses detected i.e. "
    "fragments of known license text",
}

# Attributes from a license match to keep in AnalysisResult.license_match_post_analysis
MATCH_ATTRIBUTES_TO_KEEP = [
    "key",
    "matched_text",
]


class AnalysisResult:
    """
    An AnalysisResult object holds the analysis results for a file-region, containing
    one/multiple license matches.
    A file has one or more file-regions, which are separate regions of the file
    containing some license information (separated by code/text/others in between).
    """

    def __init__(self):
        self.start_line_region = None
        self.end_line_region = None

        # A list of license matches that are detected by scancode in this region
        self.license_matches = None

        # The single license match from the region which could be
        #   1. Stitched together from multiple fragments of multiple incomplete
        #      license matches
        #   2. There's only one license match, or multiple license matches
        #      joined with AND/OR/EXCEPT
        self.license_match_post_analysis = None

        self.license_scan_analysis_result = None
        self.license_scan_analysis_result_description = None

        self.region_license_error_case = None
        self.region_license_error_case_description = None

        self.region_license_error_sub_case = None
        self.region_license_error_sub_case_description = None

    def to_dict(self):
        """
        Return a dictionary with all the class attributes as key-value pairs.
        This is the dictionary which will be added as a result of the analysis,
        in a list, as a scancode 'resource_attribute'.

        :return license_match_error: dict
        """
        license_match_error_result = {
            "start_line_region": self.start_line_region,
            "end_line_region": self.end_line_region,
            "license_matches": self.license_matches,
            "license_scan_analysis_result": self.license_scan_analysis_result,
            "license_scan_analysis_result_description":
                self.license_scan_analysis_result_description,
            "region_license_error_case": self.region_license_error_case,
            "region_license_error_case_description":
                self.region_license_error_case_description,
            "region_license_error_sub_case": self.region_license_error_sub_case,
            "region_license_error_sub_case_description":
                self.region_license_error_sub_case_description,
            "license_match_post_analysis": self.license_match_post_analysis,
        }

        return license_match_error_result


def is_correct_detection(matched_licenses):
    """
    Return True if all the license matches in a file-region are correct
    license detections, as they are either SPDX license tags, or the file content has
    a exact match with a license hash.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
    matchers = (
        matched_license["matched_rule"]["matcher"]
        for matched_license in matched_licenses
    )
    return all(matcher in ("1-hash", "4-spdx-id") for matcher in matchers)


def is_match_coverage_less_than_threshold(matched_licenses, threshold):
    """
    Returns True if any of the license matches in a file-region has a `match_coverage`
    value below the threshold.

    :param matched_licenses: list
        List of license matches in a file-region.
    :param threshold: int
        A `match_coverage` threshold value in between 0-100
    """
    coverage_values = (
        matched_license["matched_rule"]["match_coverage"]
        for matched_license in matched_licenses
    )
    return any(coverage_value < threshold for coverage_value in coverage_values)


def calculate_query_coverage_coefficient(matched_license):
    """
    Calculates a `query_coverage_coefficient` value for that match. For a match:
    1. If this value is 0, i.e. `score`==`match_coverage`*`rule_Relevance`, then
       there are no extra words in that license match.
    2. If this value is a +ve number, i.e. `score`!=`match_coverage`*`rule_Relevance`,
       then there are extra words in that match.

    :param matched_license: dict
        A license match dictionary containing all the match attributes.
    """
    matched_rule = matched_license["matched_rule"]
    score_coverage_relevance = (
        matched_rule["match_coverage"] * matched_rule["rule_relevance"]
    ) / 100

    return score_coverage_relevance - matched_license["score"]


def is_extra_words(matched_licenses):
    """
    Return True if any of the license matches in a file-region has extra words. Having
    extra words means contains a perfect match with a license/rule, but there are some
    extra words in addition to the matched text.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
    match_query_coverage_diff_values = (
        calculate_query_coverage_coefficient(matched_license)
        for matched_license in matched_licenses
    )
    return any(
        match_query_coverage_diff_value > 0
        for match_query_coverage_diff_value in match_query_coverage_diff_values
    )


def is_false_positive(matched_licenses):
    """
    Return True if all of the license matches in a file-region are false positives.
    False Positive occurs when other text/code is falsely matched to a license rule,
    because it matches with a one-word license rule with it's `is_license_tag` value as
    True. Note: Usually if it's a false positive, there's only one match in that region.

    :param matched_licenses: list
        List of license matches in a file-region.
    """
    match_rule_length_values = (
        matched_license["matched_rule"]["rule_length"]
        for matched_license in matched_licenses
    )
    match_is_license_tag_flags = (
        matched_license["matched_rule"]["is_license_tag"]
        for matched_license in matched_licenses
    )
    return all(
        (is_license_tag_flag and match_rule_length == 1)
        for is_license_tag_flag, match_rule_length in zip(
            match_is_license_tag_flags, match_rule_length_values
        )
    )


def determine_license_scan_analysis_result_for_region(
    matched_licences, analysis_result
):
    """
    Analyse license matches from a file-region, and determine if the license detection
    in that file region (i.e. group of matches coming from one location in a file)
    is correct or it is wrong/partially-correct/there's scope of improvement.
    Group these incorrect matches by analysing their attributes.

    :param matched_licences: list
        List of matched licenses in a file-region.
    :param analysis_result:
        An AnalysisResult object, containing analysis results for the matches in
        that file-region
    """
    # Case where all matches have `matcher` as `1-hash` or `4-spdx-id`
    is_correct_license_detection = is_correct_detection(matched_licences)
    if is_correct_license_detection:
        analysis_result.license_scan_analysis_result = "correct-license-detection"

    # Case where at least one of the matches have `match_coverage`
    # below IMPERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(
        matched_licences, IMPERFECT_MATCH_COVERAGE_THR
    ):
        analysis_result.license_scan_analysis_result = "imperfect-match-coverage"

    # Case where at least one of the matches have `match_coverage`
    # below NEAR_PERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(
        matched_licences, NEAR_PERFECT_MATCH_COVERAGE_THR
    ):
        analysis_result.license_scan_analysis_result = "near-perfect-match-coverage"

    # Case where at least one of the match have extra words
    elif is_extra_words(matched_licences):
        analysis_result.license_scan_analysis_result = "extra-words"

    # Case where the match is a false positive
    elif is_false_positive(matched_licences):
        if not USE_FALSE_POSITIVE_BERT_MODEL:
            analysis_result.license_scan_analysis_result = "false-positive"
        else:
            determine_false_positive_case_using_bert(matched_licences, analysis_result)

    # Cases where Match Coverage is a perfect 100 for all matches
    else:
        analysis_result.license_scan_analysis_result = "correct-license-detection"
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
    match_is_license_case_flags = (
        matched_license["matched_rule"][license_case]
        for matched_license in matched_licenses
    )
    return any(
        match_is_license_case for match_is_license_case in match_is_license_case_flags
    )


def determine_license_error_case_by_rule_type(
    matched_licences, analysis_result, is_license_text, is_legal
):
    """
    For a group of matches (which some issue) in a file-region, classify them into
    groups according to their license rule type (text/notice/tag/reference).

    :param matched_licences: list
        A list of all matches in a file-region.
    :param analysis_result:
        An AnalysisResult object, containing analysis results for the file-region
    :param is_license_text: bool
    :param is_legal: bool
    """
    # Case where at least one of the matches is matched to a `text` rule.
    if (
        is_license_text
        or is_legal
        or is_license_case(matched_licences, "is_license_text")
    ):
        analysis_result.region_license_error_case = "text"

    # Case where at least one of the matches is matched to a `notice` rule.
    elif is_license_case(matched_licences, "is_license_notice"):
        analysis_result.region_license_error_case = "notice"

    # Case where at least one of the matches is matched to a `tag` rule.
    elif is_license_case(matched_licences, "is_license_tag"):
        analysis_result.region_license_error_case = "tag"

    # Case where at least one of the matches is matched to a `reference` rule.
    elif is_license_case(matched_licences, "is_license_reference"):
        analysis_result.region_license_error_case = "reference"


def determine_license_error_case_by_rule_type_using_bert(
    matched_licences, results_grouped_by_location
):
    raise NotImplementedError


def determine_false_positive_case_using_bert(
    matched_licences, results_grouped_by_location
):
    raise NotImplementedError


def determine_license_error_sub_case_rule_type(
    matched_licences, results_grouped_by_location
):
    raise NotImplementedError


def merge_string_without_overlap(string1, string2):
    """
    Merge two Strings that doesn't have any common substring.
    """
    return string1 + "\n" + string2


def merge_string_with_overlap(string1, string2):
    """
    Merge two Strings that has a common substring.
    """
    idx = 0
    while not string2.startswith(string1[idx:]):
        idx += 1
    return string1[:idx] + string2


def get_start_end_line(grouped_matches):
    region_end_line = max([match["end_line"] for match in grouped_matches])
    region_start_line = min([match["start_line"] for match in grouped_matches])

    return region_start_line, region_end_line


def predict_license_key(grouped_matches):
    """
    Return the License Key of the match with the highest "matched_length".
    This cannot always predict the correct license key, but is a reasonable prediction
    which comes true in most cases.
    """
    # TODO: Aggregate all keys, and key with most occurrences could be the prediction
    max_match_length = max(
        [match["matched_rule"]["matched_length"] for match in grouped_matches]
    )
    key_prediction = next(
        match["key"]
        for match in grouped_matches
        if match["matched_rule"]["matched_length"] is max_match_length
    )
    return key_prediction


def get_license_match_from_region(grouped_matches, analysis_result):
    if analysis_result == "correct-license-detection":
        return None
    elif len(grouped_matches) == 1:
        [match] = grouped_matches
        match = {key: match[key] for key in MATCH_ATTRIBUTES_TO_KEEP}
    else:
        # TODO: Except sub-case "notice-and-or-except-notice"
        # as there are rightly multiple matches in a file region in this case
        # and thus the matches shouldn't be joined into one match
        match = consolidate_matches_in_one_region(grouped_matches)

    return match


def consolidate_matches_in_one_region(matches):
    """
    Craft Rule from a group of Matches, which are in the same file-region.
    The license matches are incorrect matches and has fragments of a larger text,
    but, may not contain the entire text even after consolidating.
    """

    rule_text = None
    string_end_line = None
    is_first_group = True

    for match in matches:
        if is_first_group:
            string_end_line = match["end_line"]
            rule_text = match["matched_text"]
            is_first_group = False
            continue
        else:
            present_start_line = match["start_line"]
            present_end_line = match["end_line"]
            present_text = match["matched_text"]

        # Case: Has a line-overlap
        if string_end_line == present_start_line:
            rule_text = merge_string_with_overlap(rule_text, present_text)
            string_end_line = present_end_line

        # Case: Boundary doesn't overlap but just beside
        elif string_end_line < present_start_line:
            rule_text = merge_string_without_overlap(rule_text, present_text)
            string_end_line = present_end_line

        # Case: Deep Overlaps (Of more than one lines)
        elif string_end_line > present_start_line:
            if string_end_line < present_end_line:
                rule_text = merge_string_with_overlap(rule_text, present_text)
                string_end_line = present_end_line

    # Predict Key of the crafted Rule based on the keys of the fragment matches
    key_prediction = predict_license_key(matches)

    match = {
        # "path": path,
        # "rule_class": rule_class,
        # "start_line": string_start_line,
        # "end_line": string_end_line,
        "key": key_prediction,
        "rule_text": rule_text,
    }

    return match


def analyze_region_for_license_scan_errors(matched_licences, is_license_text, is_legal):
    """
    On a group of license matches (grouped on the basis of location in file),
    perform steps of analysis to determine if the license match is correct or if it has
    any issues. In case of issues, divide the issues into groups of commonly occurring
    license detection issues.

    :param matched_licences: list
        A list of all matches in a file-region.
    :param is_license_text: bool
    :param is_legal: bool
    :returns results_grouped_by_location: object
        An AnalysisResult object, containing the analysis results for all the matches
        in the corresponding file-region.
    """
    results_grouped_by_location = AnalysisResult()

    is_correct_license_detection = determine_license_scan_analysis_result_for_region(
        matched_licences, results_grouped_by_location
    )

    # If one of the matches in the file-region has issues, classify the type of error
    # into further types of errors
    if not is_correct_license_detection:

        if not USE_LICENSE_CASE_BERT_MODEL:
            determine_license_error_case_by_rule_type(
                matched_licences, results_grouped_by_location, is_license_text, is_legal
            )
        else:
            determine_license_error_case_by_rule_type_using_bert(
                matched_licences, results_grouped_by_location
            )

        # TODO: Implement the sub-cases detection
        # determine_license_error_sub_case_rule_type(
        #   matched_licences,
        #   results_grouped_by_location
        #   )

    return results_grouped_by_location


def format_analysis_result(analysis, grouped_matches):
    """
    Format the analysis result with the following additions:-
    1. All Matches for the corresponding group
    2. A result match if there's a license detection error
    3. Description of the analysis Results for better understanding the results
    4. Start/End Line for the file-regions

    :param analysis: object
        An AnalysisResult object containing the analysis result for  a file-region.
    :param grouped_matches: list
        All matches for a group (for a file-region).
    """
    analysis.start_line_region, analysis.end_line_region = get_start_end_line(
        grouped_matches
    )

    analysis.license_matches = grouped_matches
    analysis.license_match_post_analysis = get_license_match_from_region(
        grouped_matches, analysis.license_scan_analysis_result
    )

    analysis.license_scan_analysis_result_description = DESCRIPTIONS_ANALYSIS_RESULT[
        analysis.license_scan_analysis_result
    ]

    if analysis.region_license_error_case:
        analysis.region_license_error_case_description = DESCRIPTIONS_ERROR_CASE[
            analysis.region_license_error_case
        ]

    if analysis.region_license_error_sub_case:
        analysis.region_license_error_sub_case_description = (
            DESCRIPTIONS_ERROR_SUB_CASE[analysis.region_license_error_sub_case]
        )


def group_matches(matches, lines_threshold=LINES_THRESHOLD):
    """
    Given a list of `matches` yield lists of grouped matches together where each
    group is less than `lines_threshold` apart.
    Each item in `matches` is a ScanCode matched license using the structure
    that is found in the JSON scan results.

    :param matches: list
        List of license matches in a file, which are to be grouped.
    :param lines_threshold: int
        The maximum space that can exist between two matches for them to be
        considered in the same file-region.
    :returns: list generator
        A list of groups, where each group is a list of matches in the same file-region.
    """
    group = []
    for match in matches:
        if not group:
            group.append(match)
            continue
        previous = group[-1]
        is_in_group = match["start_line"] <= previous["end_line"] + lines_threshold
        if is_in_group:
            group.append(match)
            continue
        else:
            yield group
            group = [match]

    yield group


def analyze_matches(all_groups, is_license_text, is_legal):
    """
    Analyze all license matches in a file, one group (for each file-region) at a time,
    for license detection errors.

    :param all_groups: list generator
        A list of groups, where each group is a list of matches (in a file-region).
    :param is_license_text: bool
    :param is_legal: bool
    :returns: list generator
        A list of AnalysisResult objects one for each file-region
        (each having one/multiple matches) in the file.
    """
    for group in all_groups:
        analysis = analyze_region_for_license_scan_errors(
            matched_licences=group,
            is_license_text=is_license_text,
            is_legal=is_legal,
        )
        format_analysis_result(analysis, group)
        yield analysis


def analyze_license_matches(matched_licences, is_license_text=False, is_legal=False):
    """
    Returns the results of the license detection error analysis, for all the
    license matches in a file.

    :param matched_licences: list
        A list of all matches in a file.
    :param is_license_text: bool
        A Scancode `resource_attribute` for the file. True if more than 90% of a file
        has license text.
    :param is_legal: bool
        A Scancode `resource_attribute` for the file. True if the file has a
        common legal name.
    :returns analysis_results: list
        A list of dicts, with keys corresponding to their AnalysisResult objects,
        for each file-region in the file (each having one/multiple matches in them),
        having the analysis results on the license detections.
    """
    if not matched_licences:
        return []

    all_groups = group_matches(matched_licences)
    analysis_results = analyze_matches(all_groups, is_license_text, is_legal)
    analysis_results = [ar.to_dict() for ar in analysis_results]
    return analysis_results
