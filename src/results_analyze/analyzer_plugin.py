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

import attr

from commoncode.cliutils import PluggableCommandLineOption
from commoncode.cliutils import POST_SCAN_GROUP
from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl

from results_analyze import analyzer


class NotAnalyzableResourceException(Exception):
    pass


@post_scan_impl
class ResultsAnalyzer(PostScanPlugin):
    """
    Add the "license_detection_errors" list which has the license detection error
    type information for each match errors.
    """

    resource_attributes = {
        "license_detection_analysis": attr.ib(default=attr.Factory(list))
    }

    sort_order = 80

    options = [
        PluggableCommandLineOption(
            ("--analyze-license-results",),
            is_flag=True,
            default=False,
            help='Performs a license detection analysis to detect different kinds of '
                 'potential license detection issues in scancode. '
                 'Required scancode CLI options to run this analysis are:'
                 '--license --license-text --is-license-text --classify --info',
            help_group=POST_SCAN_GROUP,
        ),
    ]

    def is_enabled(self, analyze_license_results, **kwargs):
        return analyze_license_results

    def process_codebase(self, codebase, **kwargs):
        for resource in codebase.walk():
            if not resource.is_file:
                continue

            try:
                # Will fail if missing attributes
                is_resource_validated = validate_resource(resource)
            except NotAnalyzableResourceException as e:
                msg = str(e)
                codebase.errors.append(msg)
                break

            if is_resource_validated:
                resource.license_detection_analysis = analyze_resource(resource)
                codebase.save_resource(resource)


def validate_resource(resource):
    """
    Return True if resource has all the data required for the analysis.
    Return False if the resource does not have detected licenses.
    Raise an exception if any of the essential attributes are missing from the resource.
    """
    has_licenses = hasattr(resource, "licenses")
    licenses = getattr(resource, "licenses", [])
    if has_licenses and not licenses:
        return False

    has_license_text = hasattr(resource, "is_license_text")
    has_legal = hasattr(resource, "is_legal")
    has_matched_text = all(
        "matched_text" in license_match for license_match in licenses
    )

    if has_licenses and has_license_text and has_matched_text and has_legal:
        return True

    raise NotAnalyzableResourceException(
        f"{resource.path} cannot be analyzed for license scan errors, "
        f"required attributes are: is_license_text, is_legal, license.matched_text. "
        f"Rerun scan with these options: "
        f"--license --license-text --is-license-text --classify --info"
    )


def analyze_resource(resource):
    """
    Analyzes license scan attributes for a resource and classifies license scan issues.

    :param resource: object
        An object of the commoncode.Resource class, having all resource level scan-data.
    :return: dict
        Resource attribute containing license scan analysis result for the resource.
    """
    has_attributes_for_analysis = validate_resource(resource)

    if not has_attributes_for_analysis:
        return []

    licenses = getattr(resource, "licenses")
    is_license_text = getattr(resource, "is_license_text", False)
    is_legal = getattr(resource, "is_legal", False)

    return analyzer.analyze_license_matches(
        matched_licences=licenses,
        is_license_text=is_license_text,
        is_legal=is_legal,
    )
