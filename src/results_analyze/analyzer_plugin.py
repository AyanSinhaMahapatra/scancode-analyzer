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


@post_scan_impl
class ResultsAnalyzer(PostScanPlugin):
    """
    Add the "license_detection_errors" list which has the license detection error
    type information for each match errors.
    """

    resource_attributes = {'license_detection_errors': attr.ib(default=attr.Factory(list))}

    sort_order = 80

    options = [
        PluggableCommandLineOption(
            ('--analyze-results',),
            is_flag=True,
            default=False,
            help='Add the "license_detection_errors" list which has the'
                 'license detection error type information for each match errors',
            help_group=POST_SCAN_GROUP,
        ),
    ]

    def is_enabled(self, analyze_results, **kwargs):
        return analyze_results

    def process_codebase(self, codebase, **kwargs):

        for resource in codebase.walk():

            if not resource.is_file:
                continue

            if not getattr(resource, 'licenses'):
                continue

            resource.license_detection_errors = analyze_resource(resource)
            codebase.save_resource(resource)


def analyze_resource(resource):

    licenses = getattr(resource, 'licenses')

    if not licenses:
        return []

    is_license_text = getattr(resource, 'is_license_text', False)
    is_legal = getattr(resource, 'is_legal', False)

    matched_licences = licenses

    return analyzer.analyze_license_matches(
        is_license_text=is_license_text,
        is_legal=is_legal,
        matched_licences=matched_licences,
    )
