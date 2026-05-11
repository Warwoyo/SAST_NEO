#!/usr/bin/env python3
"""Ground-truth tests for OJS source code CVE rules.

This script builds minimal vulnerable and patched fixtures for each CVE rule
in cve_ojs.yaml, runs the source code scanner, and prints a manual review
summary. It defaults to taint disabled to match the CLI behavior when using
cve_ojs rules.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ojs_sast.categories.source_code.scanner import SourceCodeScanner
from ojs_sast.rules.loader import RuleLoader


@dataclass
class TestCase:
    rule_id: str
    rel_path: str
    vulnerable: str
    patched: str
    allow_extras: set[str] = field(default_factory=set)


def build_cases() -> list[TestCase]:
    cases: list[TestCase] = []

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-001-V33",
            rel_path="plugins/importexport/native/filter/NativeXmlIssueGalleyFilter.inc.php",
            vulnerable="""<?php
class NativeXmlIssueGalleyFilter {
    public function handleElement($node) {
        $o = $node;
        $issueFile = new IssueFile();
        switch ($node->nodeName) {
            case 'file_name':
                $issueFile->setServerFileName($o->textContent);
                break;
        }
    }
}
""",
            patched="""<?php
class NativeXmlIssueGalleyFilter {
    public function handleElement($node) {
        $o = $node;
        $issueFile = new IssueFile();
        switch ($node->nodeName) {
            case 'file_name':
                $issueFile->setServerFileName(trim(
                    preg_replace(
                        "/[^a-z0-9\\.\\-]+/",
                        "",
                        str_replace(
                            [' ', '_', ':'],
                            '-',
                            strtolower($o->textContent)
                        )
                    )
                ));
                break;
        }
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-001-V34V35",
            rel_path="plugins/importexport/native/filter/NativeXmlIssueGalleyFilter.php",
            vulnerable="""<?php
class NativeXmlIssueGalleyFilter {
    public function handleElement($node) {
        $o = $node;
        $issueFile = new IssueFile();
        switch ($node->nodeName) {
            case 'file_name':
                $issueFile->setServerFileName($o->textContent);
                break;
        }
    }
}
""",
            patched="""<?php
class NativeXmlIssueGalleyFilter {
    public function handleElement($node) {
        $o = $node;
        $issueFile = new IssueFile();
        switch ($node->nodeName) {
            case 'file_name':
                $issueFile->setServerFileName(trim(
                    preg_replace(
                        "/[^a-z0-9\\.\\-]+/",
                        "",
                        str_replace(
                            [' ', '_', ':'],
                            '-',
                            strtolower($o->textContent)
                        )
                    )
                ));
                break;
        }
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-002-V33",
            rel_path="plugins/themes/default/DefaultThemePlugin.inc.php",
            vulnerable="""<?php
class DefaultThemePlugin {
    public function init() {
        if ($this->getOption('baseColour') !== '#1E6292') {
            $additionalLessVariables[] = '@bg-base:' . $this->getOption('baseColour') . ';';
        }
    }

    public function saveOption($name, $value, $contextId = null) {
        return $value;
    }
}
""",
            patched="""<?php
class DefaultThemePlugin {
    public function init() {
        $baseColour = $this->getOption('baseColour');
        if (!preg_match('/^#[0-9a-fA-F]{1,6}$/', $baseColour)) {
            $baseColour = '#1E6292';
        }
        $additionalLessVariables[] = '@bg-base:' . $baseColour . ';';
    }

    public function saveOption($name, $value, $contextId = null) {
        if ($name === 'baseColour' && !preg_match('/^#[0-9a-fA-F]{1,6}$/', $value)) {
            $value = null;
        }
        return $value;
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-002-V34V35",
            rel_path="plugins/themes/default/DefaultThemePlugin.php",
            vulnerable="""<?php
class DefaultThemePlugin {
    public function init() {
        if ($this->getOption('baseColour') !== '#1E6292') {
            $additionalLessVariables[] = '@bg-base:' . $this->getOption('baseColour') . ';';
        }
    }
}
""",
            patched="""<?php
class DefaultThemePlugin {
    public function init() {
        $baseColour = $this->getOption('baseColour');
        if (!preg_match('/^#[0-9a-fA-F]{1,6}$/', $baseColour)) {
            $baseColour = '#1E6292';
        }
        $additionalLessVariables[] = '@bg-base:' . $baseColour . ';';
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-003",
            rel_path="classes/institution/Collector.php",
            vulnerable="""<?php
class Collector {
    public function getQueryBuilder($qb, $word) {
        $qb->where(DB::raw("lower('%{$word}%')"));
    }
}
""",
            patched="""<?php
class Collector {
    public function getQueryBuilder($qb, $word) {
        $qb->where(DB::raw('lower(?)'));
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-004-V33",
            rel_path="classes/security/Validation.inc.php",
            vulnerable="""<?php
function login($username, $password, &$reason, $remember = false) {
    if ($user->getAuthId()) {
        return true;
    }
    return false;
}
""",
            patched="""<?php
function login($username, $password, &$reason, $remember = false) {
    $request = Application::get()->getRequest();
    if (!$request->checkCSRF()) {
        return false;
    }
    if ($user->getAuthId()) {
        return true;
    }
    return false;
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-004-V34V35",
            rel_path="classes/security/Validation.php",
            vulnerable="""<?php
function login($username, $password, &$reason, $remember = false) {
    $rehash = null;
    if (!self::verifyPassword($username, $password, $user->getPassword(), $rehash)) {
        return false;
    }
    return true;
}
""",
            patched="""<?php
function login($username, $password, &$reason, $remember = false) {
    $request = Application::get()->getRequest();
    if (!$request->checkCSRF()) {
        return false;
    }
    $rehash = null;
    if (!self::verifyPassword($username, $password, $user->getPassword(), $rehash)) {
        return false;
    }
    return true;
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-005",
            rel_path="plugins/importexport/native/filter/PKPNativeFilterHelper.php",
            vulnerable="""<?php
class PKPNativeFilterHelper {
    public function parsePublicationCover($filter, $node, $object) {
        $n = $node;
        $coverImage['uploadName'] = $n->textContent;
    }
}
""",
            patched="""<?php
class PKPNativeFilterHelper {
    public function parsePublicationCover($filter, $node, $object) {
        $n = $node;
        $coverImage['uploadName'] = uniqid() . '-' . basename(preg_replace(
            "/[^a-z0-9\\.\\-]+/",
            "",
            str_replace(
                [' ', '_', ':'],
                '-',
                strtolower($n->textContent)
            )
        ));
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-006",
            rel_path="templates/frontend/pages/submissions.tpl",
            vulnerable="""{translate key=about.onlineSubmissions.submitToSection name=$section->getLocalizedTitle() url=$sectionSubmissionUrl}
""",
            patched="""{translate key=about.onlineSubmissions.submitToSection name=$section->getLocalizedTitle()|escape url=$sectionSubmissionUrl}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-007",
            rel_path="classes/subscription/form/PaymentTypesForm.inc.php",
            vulnerable="""<?php
class PaymentTypesForm extends Form {
    public function __construct() {
        $this->addCheck(new FormValidatorCustom($this, 'membershipFee', 'optional', 'manager.payment.form.numeric', function($membershipFee) {
            return is_numeric($membershipFee) && $membershipFee >= 0;
        }));
    }
}
""",
            patched="""<?php
class PaymentTypesForm extends Form {
    public function __construct() {
        $this->addCheck(new FormValidatorCustom($this, 'membershipFee', 'optional', 'manager.payment.form.numeric', function($membershipFee) {
            return is_numeric($membershipFee) && $membershipFee >= 0;
        }));
        $this->addCheck(new FormValidatorCSRF($this));
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-008-A",
            rel_path="pages/management/PKPToolsHandler.inc.php",
            vulnerable="""<?php
class PKPToolsHandler {
    public function generateReport($request) {
        $filters = unserialize($request->getUserVar('filters'));
        return $filters;
    }
}
""",
            patched="""<?php
class PKPToolsHandler {
    public function generateReport($request) {
        $filters = json_decode($request->getUserVar('filters'), true);
        return $filters;
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-008-B",
            rel_path="classes/statistics/PKPStatisticsHelper.inc.php",
            vulnerable="""<?php
class PKPStatisticsHelper {
    public function getReportUrl($filter) {
        $filterEncoded = serialize($filter);
        return $filterEncoded;
    }
}
""",
            patched="""<?php
class PKPStatisticsHelper {
    public function getReportUrl($filter) {
        $filterEncoded = json_encode($filter);
        return $filterEncoded;
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-009",
            rel_path="plugins/paymethod/manual/templates/paymentForm.tpl",
            vulnerable="""<p>{$manualInstructions|nl2br}</p>
""",
            patched="""<p>{$manualInstructions|strip_unsafe_html|nl2br}</p>
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-010-V33",
            rel_path="controllers/grid/issues/IssueGridCellProvider.inc.php",
            vulnerable="""<?php
function issueLabel($issue) {
    return __('editor.issues.editIssue', array(
        'issueIdentification' => $issue->getIssueIdentification()
    ));
}
""",
            patched="""<?php
function issueLabel($issue) {
    return __('editor.issues.editIssue', array(
        'issueIdentification' => htmlspecialchars($issue->getIssueIdentification())
    ));
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-010-V34V35",
            rel_path="controllers/grid/issues/IssueGridCellProvider.php",
            vulnerable="""<?php
function issueLabel($issue) {
    return __('editor.issues.editIssue', [
        'issueIdentification' => $issue->getIssueIdentification()
    ]);
}
""",
            patched="""<?php
function issueLabel($issue) {
    return __('editor.issues.editIssue', [
        'issueIdentification' => htmlspecialchars($issue->getIssueIdentification())
    ]);
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-011",
            rel_path="templates/frontend/pages/search.tpl",
            vulnerable="""<input type=text name=authors value=
"{$authors}">
""",
            patched="""<input type=text name=authors value=
"{$authors|escape}">
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-012",
            rel_path="classes/core/PKPRequest.inc.php",
            vulnerable="""<?php
class PKPRequest {
    public function getServerHost($default) {
        $serverHost = $_SERVER[
        'HTTP_HOST'
        ];
        return $serverHost ?: $default;
    }
}
""",
            patched="""<?php
class PKPRequest {
    public function getServerHost($default) {
        $serverHost = $_SERVER[
        'HTTP_HOST'
        ];
        if (in_array($serverHost, $allowedHosts)) {
            return $serverHost;
        }
        return $default;
    }
}
""",
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-013",
            rel_path="controllers/grid/queries/QueryTitleGridColumn.php",
            vulnerable="""<?php
class QueryTitleGridColumn {
    public function getCellActions($request, $row) {
        $url = $this->getUrl($request, $row);
        $headNote = $this->getHeadNote();
        new AjaxModal($url, $headNote->getTitle(), 1);
    }

    private function getUrl($request, $row) { return $row; }
    private function getHeadNote() { return $this; }
    public function getTitle() { return "t"; }
}
""",
            patched="""<?php
class QueryTitleGridColumn {
    public function getCellActions($request, $row) {
        $url = $this->getUrl($request, $row);
        $headNote = $this->getHeadNote();
        new AjaxModal($url, htmlspecialchars($headNote->getTitle()), 1);
    }

    private function getUrl($request, $row) { return $row; }
    private function getHeadNote() { return $this; }
    public function getTitle() { return "t"; }
}
""",
            allow_extras={"OJS-SC-CVE-014"},
        )
    )

    cases.append(
        TestCase(
            rule_id="OJS-SC-CVE-014",
            rel_path="lib/pkp/controllers/grid/queries/QueryTitleGridColumn.php",
            vulnerable="""<?php
class QueryTitleGridColumn {
    public function getCellActions($request, $row) {
        $url = $this->getUrl($request, $row);
        $headNote = $this->getHeadNote();
        new AjaxModal($url, $headNote->getTitle(), 1);
    }

    private function getUrl($request, $row) { return $row; }
    private function getHeadNote() { return $this; }
    public function getTitle() { return "t"; }
}
""",
            patched="""<?php
class QueryTitleGridColumn {
    public function getCellActions($request, $row) {
        $url = $this->getUrl($request, $row);
        $headNote = $this->getHeadNote();
        new AjaxModal($url, htmlspecialchars($headNote->getTitle()), 1);
    }

    private function getUrl($request, $row) { return $row; }
    private function getHeadNote() { return $this; }
    public function getTitle() { return "t"; }
}
""",
            allow_extras={"OJS-SC-CVE-013"},
        )
    )

    return cases


def load_rules(rules_path: Path) -> list:
    loader = RuleLoader()
    loaded = loader.load_file(str(rules_path))
    if loaded == 0:
        raise RuntimeError(f"No rules loaded from {rules_path}")
    return loader.rules


def run_scan(rules: list, root: Path, enable_taint: bool) -> list[str]:
    scanner = SourceCodeScanner(
        rules,
        str(root),
        disable_taint=not enable_taint,
        ojs_version=None,
    )
    findings = scanner.scan()
    return sorted({f.rule_id for f in findings})


def run_case(case: TestCase, rules: list, enable_taint: bool) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    for variant, content in ("vulnerable", case.vulnerable), ("patched", case.patched):
        with tempfile.TemporaryDirectory(prefix="ojs_sast_gt_") as tmpdir:
            root = Path(tmpdir) / "ojs_root"
            file_path = root / case.rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
            results[variant] = run_scan(rules, root, enable_taint)
    return results


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    default_rules = repo_root / "ojs_sast" / "categories" / "source_code" / "rules" / "cve_ojs.yaml"

    parser = argparse.ArgumentParser(
        description="Run ground-truth tests for OJS source code CVE rules."
    )
    parser.add_argument(
        "--rules",
        default=str(default_rules),
        help="Path to cve_ojs.yaml (default: repo rules file)",
    )
    parser.add_argument(
        "--enable-taint",
        action="store_true",
        help="Enable taint analysis (default: disabled)",
    )
    args = parser.parse_args()

    try:
        rules = load_rules(Path(args.rules))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    cases = build_cases()
    total_checks = 0
    failed_checks = 0

    for case in cases:
        results = run_case(case, rules, args.enable_taint)
        print(f"\n[{case.rule_id}] {case.rel_path}")

        for variant in ("vulnerable", "patched"):
            total_checks += 1
            found = results[variant]
            has_expected = case.rule_id in found
            expected = variant == "vulnerable"
            ok = has_expected == expected
            status = "PASS" if ok else "FAIL"
            if not ok:
                failed_checks += 1

            found_str = "YES" if has_expected else "NO"
            exp_str = "YES" if expected else "NO"
            print(f"  {variant:10} expected={exp_str} found={found_str} {status}")

            extras = set(found) - {case.rule_id}
            unexpected = extras - case.allow_extras
            if unexpected:
                print(f"    extra rule_ids: {', '.join(sorted(unexpected))}")

    print(f"\nSummary: {total_checks - failed_checks}/{total_checks} checks passed")
    if failed_checks:
        print("Some checks failed. Review the output above.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
