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

# Threshold Values of start line and rule length for a match to likely be a false positive
# (more than the start_line threshold and less than the rule_length threshold)
FALSE_POSITIVE_START_LINE_THRESHOLD = 1000
FALSE_POSITIVE_RULE_LENGTH_THRESHOLD = 3

# Whether to Use the NLP BERT Models
USE_LICENSE_CASE_BERT_MODEL = False
USE_FALSE_POSITIVE_BERT_MODEL = False

ERROR_CASES_VERSION = 0.1

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

    RESULT_CHOICES = {
        "correct-license-detection": "The license detection is correct",
        "imperfect-match-coverage": (
            "The license detection is incorrect, a large variation is present from the "
            "matched rule(s) and is matched to only one part of the whole text"
        ),
        "near-perfect-match-coverage": (
            "The license detection is incorrect but the match is almost correct, only "
            "small percentage of the text is not matched"
        ),
        "extra-words": (
            "A license rule from the scancode rules matches completely with a part of "
            "the text, but there's some extra words which aren't there in the rule"
        ),
        "false-positives": "A piece of code/text is incorrectly detected as a license",
    }

    ERROR_RULE_TYPE_CHOICES = {
        "is_license_text": (
            "The entire/partial license text i.e. the actual terms and conditions of "
            "the license is present in the matched text"
        ),
        "is_license_notice": (
            "A notice referencing the license name and some terms/implications are "
            "present in the matched text"
        ),
        "is_license_tag": (
            "Only a reference to a license in an existing structure is present in the "
            "matched text"
        ),
        "is_license_reference": (
            "A reference to a license in the form of a local file/online link"
        ),
    }

    ERROR_RULE_SUB_TYPE_CHOICES = {
        # `text` sub-cases
        "text-legal-lic-files": (
            "the matched text is present in a file whose name is a known legal filename"
        ),
        "text-non-legal-lic-files": (
            "the matched text isn't present in a file having a known legal filename"
        ),
        "text-lic-text-fragments": "only parts of a larger license text is detected",
        # `notice` sub-cases
        "notice-and-or-except-notice": (
            "a notice which notifies multiple licenses, as exceptions, as a choice "
            "between, or as together"
        ),
        "notice-single-key-notice": "a notice that notifies a single license",
        "notice-has-unknown-match": (
            "license references with unknown licenses detected i.e. fragments of "
            "known license text"
        ),
        "notice-false-positive": (
            "A piece of code/text is incorrectly detected as a license"
        ),
        # `tag` sub-cases
        "tag-tag-coverage": "a part of a license tag is detected",
        "tag-other-tag-structures": (
            "a new/common structure of tags are detected with scope for being "
            "handled differently"
        ),
        "tag-false-positive": (
            "A piece of code/text is incorrectly detected as a license"
        ),
        # `reference` sub-cases
        "reference-lead-in-or-unknown-refs": (
            "lead-ins to known license references are detected"
        ),
        "reference-low-coverage-refs": "license references with a incomplete match",
        "reference-to-local-file": (
            "matched to an unknown rule as the license information is present in "
            "another file, which is referred to in this matched piece of text"
        ),
        "reference-false-positive": (
            "A piece of code/text is incorrectly detected as a license"
        ),
    }

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

        # One of the ANALYSIS_CHOICES
        self.analysis = None
        self.analysis_description = None

        # One of ERROR_RULE_TYPE_CHOICES
        self.error_rule_type = None
        self.error_rule_type_description = None

        # One of ERROR_RULE_SUB_TYPE_CHOICES
        self.error_rule_sub_type = None
        self.error_rule_sub_type_description = None

    def to_dict(self):
        return {
            "start_line": self.start_line_region,
            "end_line": self.end_line_region,
            "licenses": self.license_matches,
            "analysis": self.analysis,
            "analysis_description": self.analysis_description,
            "error_rule_type": self.error_rule_type,
            "error_rule_type_description": self.error_rule_type_description,
            "error_rule_sub_type": self.error_rule_sub_type,
            "error_rule_sub_type_description": self.error_rule_sub_type_description,
            "license_match_post_analysis": self.license_match_post_analysis,
        }

    @staticmethod
    def from_license_matches(license_matches, is_license_text=False, is_legal=False):
        """
        Return a list of AnalysisResult given a list of ``license_matches`` mappings.

        :param license_matches: list
            A list of all matches in a file.
        :param is_license_text: bool
            True if most of a file is license text.
        :param is_legal: bool
            True if the file has a common legal name.
        :return analysis_results: list
            A list of AnalysisResult objects.
        """
        if not license_matches:
            return []

        groups_of_license_matches = group_matches(license_matches)
        return analyze_matches(groups_of_license_matches, is_license_text, is_legal)


def is_correct_detection(license_matches):
    """
    Return True if all the license matches in a file-region are correct
    license detections, as they are either SPDX license tags, or the file content has
    a exact match with a license hash.

    :param license_matches: list
        List of license matches in a file-region.
    """
    matchers = (match["matched_rule"]["matcher"] for match in license_matches)
    return all(matcher in ("1-hash", "4-spdx-id") for matcher in matchers)


def is_match_coverage_less_than_threshold(license_matches, threshold):
    """
    Returns True if any of the license matches in a file-region has a `match_coverage`
    value below the threshold.

    :param license_matches: list
        List of license matches in a file-region.
    :param threshold: int
        A `match_coverage` threshold value in between 0-100
    """
    coverage_values = (
        match["matched_rule"]["match_coverage"] for match in license_matches
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


def is_extra_words(license_matches):
    """
    Return True if any of the license matches in a file-region has extra words. Having
    extra words means contains a perfect match with a license/rule, but there are some
    extra words in addition to the matched text.

    :param license_matches: list
        List of license matches in a file-region.
    """
    match_query_coverage_diff_values = (
        calculate_query_coverage_coefficient(match) for match in license_matches
    )
    return any(
        match_query_coverage_diff_value > 0
        for match_query_coverage_diff_value in match_query_coverage_diff_values
    )


def is_false_positive(license_matches):
    """
    Return True if all of the license matches in a file-region are false positives.
    False Positive occurs when other text/code is falsely matched to a license rule,
    because it matches with a one-word license rule with it's `is_license_tag` value as
    True. Note: Usually if it's a false positive, there's only one match in that region.

    :param license_matches: list
        List of license matches in a file-region.
    """
    start_line_region = min(match["start_line"] for match in license_matches)
    match_rule_length_values = [
        match["matched_rule"]["rule_length"] for match in license_matches
    ]

    if start_line_region > FALSE_POSITIVE_START_LINE_THRESHOLD and any(
        match_rule_length_value <= FALSE_POSITIVE_RULE_LENGTH_THRESHOLD
        for match_rule_length_value in match_rule_length_values
    ):
        return True

    match_is_license_tag_flags = (
        match["matched_rule"]["is_license_tag"] for match in license_matches
    )
    return all(
        (is_license_tag_flag and match_rule_length == 1)
        for is_license_tag_flag, match_rule_length in zip(
            match_is_license_tag_flags, match_rule_length_values
        )
    )


def get_analysis_for_region(license_matches, analysis_result):
    """
    Analyse license matches from a file-region, and determine if the license detection
    in that file region is correct or it is wrong/partially-correct/false-positive or
    has extra words.

    :param license_matches: list
        List of matched licenses in a file-region.
    :param analysis_result:
        An AnalysisResult object
    """
    # Case where all matches have `matcher` as `1-hash` or `4-spdx-id`
    is_correct_license_detection = is_correct_detection(license_matches)
    if is_correct_license_detection:
        analysis_result.analysis = "correct-license-detection"

    # Case where at least one of the matches have `match_coverage`
    # below IMPERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(
        license_matches, IMPERFECT_MATCH_COVERAGE_THR
    ):
        analysis_result.analysis = "imperfect-match-coverage"

    # Case where at least one of the matches have `match_coverage`
    # below NEAR_PERFECT_MATCH_COVERAGE_THR
    elif is_match_coverage_less_than_threshold(
        license_matches, NEAR_PERFECT_MATCH_COVERAGE_THR
    ):
        analysis_result.analysis = "near-perfect-match-coverage"

    # Case where at least one of the match have extra words
    elif is_extra_words(license_matches):
        analysis_result.analysis = "extra-words"

    # Case where the match is a false positive
    elif is_false_positive(license_matches):
        if not USE_FALSE_POSITIVE_BERT_MODEL:
            analysis_result.analysis = "false-positive"
        else:
            determine_false_positive_case_using_bert(license_matches, analysis_result)

    # Cases where Match Coverage is a perfect 100 for all matches
    else:
        analysis_result.analysis = "correct-license-detection"
        is_correct_license_detection = True

    return is_correct_license_detection


def is_license_case(license_matches, license_case):
    """
    Get the type of license_match_case for a group of license matches in a file-region.

    :param license_matches: list
        List of matched licenses in a file-region
    :param license_case: string
        One of the 4 boolean flag attributes of a match, i.e. is it text/notice/tag/ref
    """
    match_is_license_case_flags = (
        match["matched_rule"][license_case] for match in license_matches
    )
    return any(
        match_is_license_case for match_is_license_case in match_is_license_case_flags
    )


def get_error_rule_type(license_matches, analysis_result, is_license_text, is_legal):
    """
    For a group of matches (with some issue) in a file-region, classify them into
    groups according to their potential license rule type (text/notice/tag/reference).

    :param license_matches: list
        A list of all matches in a file-region.
    :param analysis_result:
        An AnalysisResult object.
    :param is_license_text: bool
    :param is_legal: bool
    """
    # Case where at least one of the matches is matched to a `text` rule.
    if (
        is_license_text
        or is_legal
        or is_license_case(license_matches, "is_license_text")
    ):
        analysis_result.error_rule_type = "is_license_text"

    # Case where at least one of the matches is matched to a `notice` rule.
    elif is_license_case(license_matches, "is_license_notice"):
        analysis_result.error_rule_type = "is_license_notice"

    # Case where at least one of the matches is matched to a `tag` rule.
    elif is_license_case(license_matches, "is_license_tag"):
        analysis_result.error_rule_type = "is_license_tag"

    # Case where at least one of the matches is matched to a `reference` rule.
    elif is_license_case(license_matches, "is_license_reference"):
        analysis_result.error_rule_type = "is_license_reference"


def get_license_text_sub_type(is_license_text, is_legal):

    if is_license_text:
        if is_legal:
            return "text-legal-lic-files"
        else:
            return "text-non-legal-lic-files"
    else:
        return "text-lic-text-fragments"


def get_license_notice_sub_type(license_matches, analysis):

    license_expression_connectors = ["AND", "OR", "WITH"]

    match_rule_license_expressions = [
        match["matched_rule"]["license_expression"] for match in license_matches
    ]

    if analysis == "false-positive":
        return "notice-false-positive"
    elif all(
        any(
            license_expression_connector in license_expression
            for license_expression_connector in license_expression_connectors
        )
        for license_expression in match_rule_license_expressions
    ):
        return "notice-and-or-except-notice"
    elif any(
        "unknown" in license_expression
        for license_expression in match_rule_license_expressions
    ):
        return "notice-has-unknown-match"
    else:
        return "notice-single-key-notice"


def get_license_tag_sub_type(analysis):

    if analysis == "false-positive":
        return "tag-false-positive"
    else:
        return "tag-tag-coverage"


def get_license_reference_sub_type(license_matches, analysis):

    match_rule_identifiers = [
        match["matched_rule"]["identifier"] for match in license_matches
    ]

    if analysis == "false-positive":
        return "reference-false-positive"
    elif any("lead" in identifier for identifier in match_rule_identifiers):
        return "reference-lead-in-refs"
    elif any("unknown" in identifier for identifier in match_rule_identifiers):
        return "reference-has-unknown-match"
    else:
        return "reference-low-coverage-refs"


def get_error_rule_sub_type(
    license_matches, analysis_result, is_license_text, is_legal
):
    if analysis_result.error_rule_type == "is_license_text":
        analysis_result.error_rule_sub_type = get_license_text_sub_type(
            is_license_text, is_legal
        )
    elif analysis_result.error_rule_type == "is_license_notice":
        analysis_result.error_rule_sub_type = get_license_notice_sub_type(
            license_matches, analysis_result.analysis
        )
    elif analysis_result.error_rule_type == "is_license_tag":
        analysis_result.error_rule_sub_type = get_license_tag_sub_type(
            analysis_result.analysis
        )
    elif analysis_result.error_rule_type == "is_license_reference":
        analysis_result.error_rule_sub_type = get_license_reference_sub_type(
            license_matches, analysis_result.analysis
        )


def determine_error_rule_type_using_bert(license_matches, analysis_result):
    raise NotImplementedError


def determine_false_positive_case_using_bert(license_matches, analysis_result):
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


def get_start_end_line(group_of_license_matches):
    region_end_line = max([match["end_line"] for match in group_of_license_matches])
    region_start_line = min([match["start_line"] for match in group_of_license_matches])

    return region_start_line, region_end_line


def predict_license_key(group_of_license_matches):
    """
    Return the License Key of the match with the highest "matched_length".
    This cannot always predict the correct license key, but is a reasonable prediction
    which comes true in most cases.
    """
    # TODO: Aggregate all keys, and key with most occurrences could be the prediction
    max_match_length = max(
        [match["matched_rule"]["matched_length"] for match in group_of_license_matches]
    )
    key_prediction = next(
        match["key"]
        for match in group_of_license_matches
        if match["matched_rule"]["matched_length"] is max_match_length
    )
    return key_prediction


def get_license_match_from_region(group_of_license_matches, analysis_result):
    if analysis_result.analysis == "correct-license-detection":
        return None
    elif len(group_of_license_matches) == 1:
        [match] = group_of_license_matches
        match = {key: match[key] for key in MATCH_ATTRIBUTES_TO_KEEP}
    else:
        if analysis_result.error_rule_sub_type == "notice-and-or-except-notice":
            match = group_of_license_matches
        else:
            match = consolidate_matches_in_one_region(group_of_license_matches)

    return match


def consolidate_matches_in_one_region(group_of_license_matches):
    """
    Craft Rule from a group of Matches, which are in the same file-region.
    The license matches are incorrect matches and has fragments of a larger text,
    but, may not contain the entire text even after consolidating.
    """

    rule_text = None
    string_end_line = None
    is_first_group = True

    for match in group_of_license_matches:
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
    key_prediction = predict_license_key(group_of_license_matches)

    match = {
        # "path": path,
        # "rule_class": rule_class,
        # "start_line": string_start_line,
        # "end_line": string_end_line,
        "key": key_prediction,
        "rule_text": rule_text,
    }

    return match


def analyze_region_for_license_scan_errors(
    group_of_license_matches, is_license_text, is_legal
):
    """
    On a group of license matches (grouped on the basis of location in file),
    perform steps of analysis to determine if the license match is correct or if it has
    any issues. In case of issues, divide the issues into groups of commonly occurring
    license detection issues.

    :param group_of_license_matches: list
        A list of all matches in a file-region.
    :param is_license_text: bool
    :param is_legal: bool
    :returns analysis_result: object
        An AnalysisResult object, containing the analysis result for all the matches
        in the corresponding file-region.
    """
    analysis_result = AnalysisResult()

    is_correct_license_detection = get_analysis_for_region(
        group_of_license_matches, analysis_result
    )

    # If one of the matches in the file-region has issues, classify the type of error
    # into further types of errors
    if not is_correct_license_detection:

        if not USE_LICENSE_CASE_BERT_MODEL:
            get_error_rule_type(
                group_of_license_matches,
                analysis_result,
                is_license_text,
                is_legal,
            )
        else:
            determine_error_rule_type_using_bert(
                group_of_license_matches, analysis_result
            )

        get_error_rule_sub_type(
            group_of_license_matches, analysis_result, is_license_text, is_legal
        )

    return analysis_result


def format_analysis_result(analysis_result, grouped_matches):
    """
    Format the analysis result with the following additions:-
    1. All Matches for the corresponding group
    2. A result match if there's a license detection error
    3. Description of the analysis Results for better understanding the results
    4. Start/End Line for the file-regions

    :param analysis_result: object
        An AnalysisResult object containing the analysis result for  a file-region.
    :param grouped_matches: list
        All matches for a group (for a file-region).
    """
    (
        analysis_result.start_line_region,
        analysis_result.end_line_region,
    ) = get_start_end_line(grouped_matches)

    analysis_result.license_matches = grouped_matches
    analysis_result.license_match_post_analysis = get_license_match_from_region(
        grouped_matches, analysis_result
    )

    analysis_result.analysis_description = analysis_result.RESULT_CHOICES[
        analysis_result.analysis
    ]

    if analysis_result.error_rule_type:
        analysis_result.error_rule_type_description = (
            analysis_result.ERROR_RULE_TYPE_CHOICES[analysis_result.error_rule_type]
        )

    if analysis_result.error_rule_sub_type:
        analysis_result.error_rule_sub_type_description = (
            analysis_result.ERROR_RULE_SUB_TYPE_CHOICES[
                analysis_result.error_rule_sub_type
            ]
        )


def group_matches(license_matches, lines_threshold=LINES_THRESHOLD):
    """
    Given a list of `matches` yield lists of grouped matches together where each
    group is less than `lines_threshold` apart.
    Each item in `matches` is a ScanCode matched license using the structure
    that is found in the JSON scan results.

    :param license_matches: list
        List of license matches in a file, which are to be grouped.
    :param lines_threshold: int
        The maximum space that can exist between two matches for them to be
        considered in the same file-region.
    :returns: list generator
        A list of groups, where each group is a list of matches in the same file-region.
    """
    group_of_license_matches = []
    for match in license_matches:
        if not group_of_license_matches:
            group_of_license_matches.append(match)
            continue
        previous = group_of_license_matches[-1]
        is_in_group = match["start_line"] <= previous["end_line"] + lines_threshold
        if is_in_group:
            group_of_license_matches.append(match)
            continue
        else:
            yield group_of_license_matches
            group_of_license_matches = [match]

    yield group_of_license_matches


def analyze_matches(all_groups_of_license_matches, is_license_text, is_legal):
    """
    Analyze all license matches in a file, one group (for each file-region) at a time,
    for license detection errors.

    :param all_groups_of_license_matches: list generator
        A list of groups, where each group is a list of matches (in a file-region).
    :param is_license_text: bool
    :param is_legal: bool
    :returns: list generator
        A list of AnalysisResult objects one for each file-region
        (each having one/multiple matches) in the file.
    """
    for group_of_license_matches in all_groups_of_license_matches:
        analysis_result = analyze_region_for_license_scan_errors(
            group_of_license_matches=group_of_license_matches,
            is_license_text=is_license_text,
            is_legal=is_legal,
        )
        format_analysis_result(analysis_result, group_of_license_matches)
        yield analysis_result
