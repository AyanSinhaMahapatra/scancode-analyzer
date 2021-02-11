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

MISSING_OPTIONS_MESSAGE = (
    "The scan must be run with these options: "
    "--license --license-text --is-license-text --classify --info"
)


@post_scan_impl
class ResultsAnalyzer(PostScanPlugin):
    """
    Add the "license_detection_issues" list which has the analysis, type information
    and suggested license match for each license match issue.
    """

    resource_attributes = {
        "license_detection_issues": attr.ib(default=attr.Factory(list))
    }

    sort_order = 80

    options = [
        PluggableCommandLineOption(
            ("--analyze-license-results",),
            is_flag=True,
            default=False,
            help="Performs a license detection analysis to detect different kinds of "
            "potential license detection issues in scancode. "
            + MISSING_OPTIONS_MESSAGE,
            help_group=POST_SCAN_GROUP,
        ),
    ]

    def is_enabled(self, analyze_license_results, **kwargs):
        return analyze_license_results

    def process_codebase(self, codebase, **kwargs):
        msg = (
            "Cannot analyze scan for license detection errors, because "
            "required attributes are missing. " + MISSING_OPTIONS_MESSAGE,
        )

        for resource in codebase.walk():
            if not resource.is_file:
                continue

            if not hasattr(resource, "licenses"):
                codebase.errors.append(msg)
                break

            license_matches = getattr(resource, "licenses", [])
            if not license_matches:
                continue

            if not is_analyzable(resource):
                codebase.errors.append(msg)
                break

            try:
                ars = analyzer.LicenseDetectionIssue.from_license_matches(
                    license_matches=license_matches,
                    is_license_text=getattr(resource, "is_license_text", False),
                    is_legal=getattr(resource, "is_legal", False),
                )
                resource.license_detection_issues = [attr.asdict(ar) for ar in ars]
            except Exception as e:
                msg = f"Cannot analyze scan for license scan errors: {str(e)}"
                resource.scan_errors.append(msg)
            codebase.save_resource(resource)


def is_analyzable(resource):
    """
    Return True if resource has all the data required for the analysis.
    Return False if any of the essential attributes are missing from the resource.
    """
    license_matches = getattr(resource, "licenses", [])
    has_is_license_text = hasattr(resource, "is_license_text")
    has_is_legal = hasattr(resource, "is_legal")
    has_matched_text = all("matched_text" in match for match in license_matches)

    return has_is_license_text and has_matched_text and has_is_legal
