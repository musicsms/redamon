"""
Comprehensive unit tests for JS Recon Scanner modules.

Run: cd "/home/samuele/Progetti didattici/redamon" && python3 -m unittest recon.tests.test_js_recon -v
Or:  cd "/home/samuele/Progetti didattici/redamon" && python3 recon/tests/test_js_recon.py
"""

import sys
import os
import json
import tempfile
import unittest
import importlib.util

# Direct import to bypass recon/helpers/__init__.py which imports dns
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def _load_module(name, filepath):
    """Load a module directly by file path, bypassing package __init__.py."""
    spec = importlib.util.spec_from_file_location(name, filepath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BASE = os.path.join(os.path.dirname(__file__), '..')
patterns = _load_module('recon.helpers.js_recon.patterns', os.path.join(BASE, 'helpers/js_recon/patterns.py'))
validators = _load_module('recon.helpers.js_recon.validators', os.path.join(BASE, 'helpers/js_recon/validators.py'))
sourcemap = _load_module('recon.helpers.js_recon.sourcemap', os.path.join(BASE, 'helpers/js_recon/sourcemap.py'))
dependency = _load_module('recon.helpers.js_recon.dependency', os.path.join(BASE, 'helpers/js_recon/dependency.py'))
endpoints_mod = _load_module('recon.helpers.js_recon.endpoints', os.path.join(BASE, 'helpers/js_recon/endpoints.py'))
framework = _load_module('recon.helpers.js_recon.framework', os.path.join(BASE, 'helpers/js_recon/framework.py'))


# ============================================================
# PATTERNS MODULE TESTS
# ============================================================

class TestPatterns(unittest.TestCase):

    def test_patterns_compiled_count(self):
        self.assertGreaterEqual(len(patterns.JS_SECRET_PATTERNS), 90)

    def test_patterns_have_required_keys(self):
        for p in patterns.JS_SECRET_PATTERNS:
            self.assertIn('name', p)
            self.assertIn('regex', p)
            self.assertIn('severity', p)
            self.assertIn('confidence', p)
            self.assertIn('category', p)

    def test_aws_key_detection(self):
        js = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        findings = patterns.scan_js_content(js, 'test.js')
        aws = [f for f in findings if f['name'] == 'AWS Access Key ID']
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0]['severity'], 'critical')
        self.assertIn('id', aws[0])


    def test_github_token_detection(self):
        token = 'ghp_' + 'A' * 36
        js = f'const t = "{token}";'
        findings = patterns.scan_js_content(js, 'test.js')
        gh = [f for f in findings if f['name'] == 'GitHub Token Classic']
        self.assertEqual(len(gh), 1)
        self.assertEqual(gh[0]['validator_ref'], 'validate_github')

    def test_firebase_url_detection(self):
        js = 'const db = "https://myapp-12345.firebaseio.com";'
        findings = patterns.scan_js_content(js, 'test.js')
        fb = [f for f in findings if f['name'] == 'Firebase URL']
        self.assertEqual(len(fb), 1)

    def test_jwt_detection(self):
        jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        js = f'const t = "{jwt}";'
        findings = patterns.scan_js_content(js, 'test.js')
        jwts = [f for f in findings if f['name'] == 'JWT Token']
        self.assertEqual(len(jwts), 1)

    def test_email_filtering_excludes_example(self):
        js = 'const a = "admin@target.com"; const b = "user@example.com";'
        findings = patterns.scan_js_content(js, 'test.js')
        emails = [f for f in findings if f['name'] == 'Email Address']
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]['matched_text'], 'admin@target.com')

    def test_min_confidence_filter(self):
        js = 'const k = "AKIAIOSFODNN7EXAMPLE"; debug = true;'
        high = patterns.scan_js_content(js, 'test.js', min_confidence='high')
        low = patterns.scan_js_content(js, 'test.js', min_confidence='low')
        self.assertLessEqual(len(high), len(low))

    def test_deduplication(self):
        js = 'const a = "AKIAIOSFODNN7EXAMPLE";\nconst b = "AKIAIOSFODNN7EXAMPLE";'
        findings = patterns.scan_js_content(js, 'test.js')
        aws = [f for f in findings if f['name'] == 'AWS Access Key ID']
        self.assertEqual(len(aws), 1)

    def test_redaction_short_secret(self):
        js = 'key = "abcde123";'
        findings = patterns.scan_js_content(js, 'test.js')
        for f in findings:
            mt = f.get('matched_text', '')
            rv = f.get('redacted_value', '')
            if 4 < len(mt) <= 12:
                self.assertIn('...', rv, f"Short secret not redacted: {rv}")

    def test_long_line_skip(self):
        long_line = 'x' * 600_000
        findings = patterns.scan_js_content(long_line, 'test.js')
        self.assertEqual(len(findings), 0)

    def test_custom_patterns(self):
        custom = [{'name': 'MyKey', 'regex': r'MYCO-[a-f0-9]{8}', 'severity': 'critical', 'confidence': 'high'}]
        js = 'const k = "MYCO-abcd1234";'
        findings = patterns.scan_js_content(js, 'test.js', custom_patterns=custom)
        my = [f for f in findings if f['name'] == 'MyKey']
        self.assertEqual(len(my), 1)

    def test_dev_comments_have_id(self):
        js = '// TODO: remove hardcoded password\n// FIXME: temporary bypass'
        comments = patterns.scan_dev_comments(js, 'test.js')
        self.assertGreaterEqual(len(comments), 2)
        for c in comments:
            self.assertIn('id', c)

    def test_dev_comment_sensitive_severity(self):
        js = '// TODO: remove hardcoded password before deploy'
        comments = patterns.scan_dev_comments(js, 'test.js')
        self.assertTrue(any(c['severity'] == 'medium' for c in comments))

    def test_load_custom_patterns_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([{"name": "Test", "regex": "TEST-[0-9]+"}], f)
            f.flush()
            loaded = patterns.load_custom_patterns(f.name)
        os.unlink(f.name)
        self.assertEqual(len(loaded), 1)

    def test_load_custom_patterns_txt(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("MyP|MYKEY-[a-z]+|critical|high\n# comment\n")
            f.flush()
            loaded = patterns.load_custom_patterns(f.name)
        os.unlink(f.name)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]['severity'], 'critical')

    def test_s3_detection(self):
        js = 'const u = "https://mybucket.s3.amazonaws.com/file";'
        findings = patterns.scan_js_content(js, 'test.js')
        s3 = [f for f in findings if 'S3' in f['name']]
        self.assertGreaterEqual(len(s3), 1)

    def test_private_ip_detection(self):
        js = 'const s = "192.168.1.100:8080";'
        findings = patterns.scan_js_content(js, 'test.js')
        ips = [f for f in findings if f['name'] == 'Private IP (RFC1918)']
        self.assertGreaterEqual(len(ips), 1)


# ============================================================
# VALIDATORS MODULE TESTS
# ============================================================

class TestValidators(unittest.TestCase):

    def test_registry_covers_all_pattern_refs(self):
        for p in patterns.JS_SECRET_PATTERNS:
            ref = p.get('validator_ref')
            if ref:
                self.assertIn(ref, validators.VALIDATOR_REGISTRY, f"Missing validator: {ref}")

    def test_no_validator(self):
        r = validators.validate_secret('test', 'test', validator_ref=None)
        self.assertEqual(r['error'], 'no_validator')

    def test_unknown_validator(self):
        r = validators.validate_secret('test', 'test', validator_ref='nonexistent')
        self.assertEqual(r['error'], 'no_validator')

    def test_aws_incomplete(self):
        r = validators.validate_aws('AKIAIOSFODNN7EXAMPLE')
        self.assertEqual(r['error'], 'incomplete_credentials')

    def test_twilio_incomplete(self):
        r = validators.validate_twilio('AC' + 'a' * 32)
        self.assertEqual(r['error'], 'incomplete_credentials')

    def test_github_no_token(self):
        r = validators.validate_github('no token here')
        self.assertEqual(r['error'], 'no_token_found')

    def test_all_validators_return_dict(self):
        for name, func in validators.VALIDATOR_REGISTRY.items():
            r = func('dummy_text', timeout=1)
            self.assertIsInstance(r, dict, f"Validator {name} didn't return dict")
            self.assertIn('valid', r)
            self.assertIn('error', r)


# ============================================================
# SOURCEMAP MODULE TESTS
# ============================================================

class TestSourcemap(unittest.TestCase):

    def test_comment_standard(self):
        r = sourcemap.check_sourcemap_comment('var x;\n//# sourceMappingURL=app.js.map')
        self.assertEqual(r, 'app.js.map')

    def test_comment_multiline(self):
        r = sourcemap.check_sourcemap_comment('var x;\n/*# sourceMappingURL=app.js.map */')
        self.assertEqual(r, 'app.js.map')

    def test_comment_none(self):
        r = sourcemap.check_sourcemap_comment('var x = 1;')
        self.assertIsNone(r)

    def test_header_found(self):
        r = sourcemap.check_sourcemap_header({'SourceMap': '/app.js.map'})
        self.assertEqual(r, '/app.js.map')

    def test_header_none(self):
        r = sourcemap.check_sourcemap_header({'Content-Type': 'text/javascript'})
        self.assertIsNone(r)

    def test_resolve_absolute(self):
        r = sourcemap._resolve_map_url('https://a.com/app.js', 'https://b.com/app.map')
        self.assertEqual(r, 'https://b.com/app.map')

    def test_resolve_relative(self):
        r = sourcemap._resolve_map_url('https://a.com/js/app.js', 'app.js.map')
        self.assertEqual(r, 'https://a.com/js/app.js.map')

    def test_probe_urls_count(self):
        urls = sourcemap._build_probe_urls('https://a.com/js/app.js')
        self.assertGreaterEqual(len(urls), 7)

    def test_probe_urls_bad_template(self):
        urls = sourcemap._build_probe_urls('https://a.com/app.js', custom_paths=['{bad_var}'])
        self.assertIsInstance(urls, list)

    def test_analyze_basic(self):
        data = {'version': 3, 'sources': ['a.ts', 'b.ts'], 'sourcesContent': None}
        r = sourcemap.analyze_sourcemap(data, 'https://a.com/app.map', 'https://a.com/app.js')
        self.assertEqual(r['files_count'], 2)
        self.assertTrue(r['accessible'])
        self.assertIn('id', r)

    def test_disabled(self):
        r = sourcemap.discover_and_analyze_sourcemaps([], {'JS_RECON_SOURCE_MAPS': False})
        self.assertEqual(r, [])


# ============================================================
# DEPENDENCY MODULE TESTS
# ============================================================

class TestDependency(unittest.TestCase):

    def test_extract_es6(self):
        pkgs = dependency.extract_scoped_packages("import x from '@org/lib';")
        self.assertIn('@org/lib', pkgs)

    def test_extract_require(self):
        pkgs = dependency.extract_scoped_packages("require('@co/sdk');")
        self.assertIn('@co/sdk', pkgs)

    def test_extract_dynamic(self):
        pkgs = dependency.extract_scoped_packages("import('@s/mod');")
        self.assertIn('@s/mod', pkgs)

    def test_extract_export(self):
        pkgs = dependency.extract_scoped_packages("export { x } from '@o/h';")
        self.assertIn('@o/h', pkgs)

    def test_extract_none(self):
        pkgs = dependency.extract_scoped_packages("import React from 'react';")
        self.assertEqual(len(pkgs), 0)

    def test_webpack_chunk(self):
        pkgs = dependency.extract_webpack_packages('/* webpackChunkName: "@org/chunk" */')
        self.assertIn('@org/chunk', pkgs)

    def test_well_known_skipped(self):
        js_files = [{'url': 't.js', 'content': "import x from '@types/react';"}]
        settings = {'JS_RECON_DEPENDENCY_CHECK': True, 'JS_RECON_CUSTOM_PACKAGES': ''}
        findings = dependency.detect_dependency_confusion(js_files, settings)
        self.assertEqual(len(findings), 0)

    def test_disabled(self):
        r = dependency.detect_dependency_confusion([], {'JS_RECON_DEPENDENCY_CHECK': False})
        self.assertEqual(r, [])


# ============================================================
# ENDPOINTS MODULE TESTS
# ============================================================

class TestEndpoints(unittest.TestCase):

    def _scan(self, js):
        return endpoints_mod.extract_endpoints(
            [{'url': 'app.js', 'content': js}],
            {'JS_RECON_EXTRACT_ENDPOINTS': True, 'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': ''}
        )

    def test_fetch(self):
        eps = self._scan("fetch('/api/v1/users');")
        self.assertTrue(any(e['path'] == '/api/v1/users' for e in eps))

    def test_axios(self):
        eps = self._scan("axios.post('/api/login', data);")
        self.assertTrue(any(e['path'] == '/api/login' for e in eps))

    def test_websocket(self):
        eps = self._scan("new WebSocket('wss://a.com/ws');")
        self.assertTrue(any(e['type'] == 'websocket' for e in eps))

    def test_graphql_introspection(self):
        eps = self._scan("query { __schema { types { name } } }")
        self.assertTrue(any(e.get('type') == 'graphql_introspection' for e in eps))

    def test_filter_css(self):
        eps = self._scan("fetch('/styles/app.css');")
        self.assertFalse(any('.css' in e.get('path', '') for e in eps))

    def test_filter_hash_routes(self):
        eps = self._scan("path: '/#/dashboard';")
        self.assertFalse(any('/#' in e.get('path', '') for e in eps))

    def test_filter_node_modules(self):
        eps = self._scan("fetch('/node_modules/pkg/index.js');")
        self.assertFalse(any('node_modules' in e.get('path', '') for e in eps))

    def test_classify_admin(self):
        eps = self._scan("fetch('/admin/dashboard');")
        self.assertTrue(any(e.get('category') == 'admin_debug' for e in eps))

    def test_dedup(self):
        eps = self._scan("fetch('/api/a');\nfetch('/api/a');")
        a_eps = [e for e in eps if e['path'] == '/api/a']
        self.assertEqual(len(a_eps), 1)

    def test_all_have_id(self):
        eps = self._scan("fetch('/a'); fetch('/b');")
        for e in eps:
            self.assertIn('id', e)

    def test_disabled(self):
        r = endpoints_mod.extract_endpoints([], {'JS_RECON_EXTRACT_ENDPOINTS': False})
        self.assertEqual(r, [])


# ============================================================
# FRAMEWORK MODULE TESTS
# ============================================================

class TestFramework(unittest.TestCase):

    def test_detect_react(self):
        fws = framework.detect_frameworks('React.version = "18.2.0";', 'a.js')
        react = [f for f in fws if f['name'] == 'React']
        self.assertEqual(len(react), 1)
        self.assertEqual(react[0]['version'], '18.2.0')
        self.assertIn('id', react[0])

    def test_detect_nextjs(self):
        fws = framework.detect_frameworks('__NEXT_DATA__', 'a.js')
        self.assertTrue(any(f['name'] == 'Next.js' for f in fws))

    def test_detect_vue(self):
        fws = framework.detect_frameworks('Vue.version = "3.4.0";', 'a.js')
        vue = [f for f in fws if f['name'] == 'Vue.js']
        self.assertEqual(len(vue), 1)

    def test_detect_angular(self):
        fws = framework.detect_frameworks("@angular/core", 'a.js')
        self.assertTrue(any(f['name'] == 'Angular' for f in fws))

    def test_detect_jquery(self):
        fws = framework.detect_frameworks('jQuery.fn.jquery = "3.7.1";', 'a.js')
        self.assertTrue(any(f['name'] == 'jQuery' for f in fws))

    def test_no_duplicates(self):
        fws = framework.detect_frameworks('React.createElement(); React.createElement();', 'a.js')
        react = [f for f in fws if f['name'] == 'React']
        self.assertEqual(len(react), 1)

    def test_dom_sink_innerhtml(self):
        sinks = framework.detect_dom_sinks('el.innerHTML = x;', 'a.js')
        self.assertTrue(any(s['type'] == 'innerHTML' for s in sinks))
        self.assertTrue(all('id' in s for s in sinks))

    def test_dom_sink_eval(self):
        sinks = framework.detect_dom_sinks('var r = eval(code);', 'a.js')
        self.assertTrue(any(s['type'] == 'eval' for s in sinks))
        self.assertTrue(any(s['severity'] == 'critical' for s in sinks))

    def test_dom_sink_proto(self):
        sinks = framework.detect_dom_sinks('obj.__proto__.admin = true;', 'a.js')
        self.assertTrue(any(s['type'] == '__proto__' for s in sinks))

    def test_dom_sink_dedup(self):
        sinks = framework.detect_dom_sinks('el.innerHTML = x;', 'a.js')
        inner = [s for s in sinks if s['type'] == 'innerHTML']
        self.assertEqual(len(inner), 1)

    def test_custom_framework(self):
        custom = [{'name': 'MyFW', 'patterns': ['__MY_FW__'], 'version_regex': None}]
        fws = framework.detect_frameworks('window.__MY_FW__ = {};', 'a.js', custom_signatures=custom)
        self.assertTrue(any(f['name'] == 'MyFW' for f in fws))

    def test_load_custom_frameworks(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([{"name": "TFW", "patterns": ["TFW"], "version_regex": None}], f)
            f.flush()
            loaded = framework.load_custom_frameworks(f.name)
        os.unlink(f.name)
        self.assertEqual(len(loaded), 1)


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestIntegration(unittest.TestCase):

    def test_validator_refs_all_exist(self):
        for p in patterns.JS_SECRET_PATTERNS:
            ref = p.get('validator_ref')
            if ref:
                self.assertIn(ref, validators.VALIDATOR_REGISTRY)

    def test_finding_id_uniqueness(self):
        js = 'const a = "AKIAIOSFODNN7EXAMPLE"; const b = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";'
        findings = patterns.scan_js_content(js, 'test.js')
        ids = [f['id'] for f in findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_modules_return_list(self):
        self.assertIsInstance(patterns.scan_js_content('x', 't.js'), list)
        self.assertIsInstance(patterns.scan_dev_comments('x', 't.js'), list)
        self.assertIsInstance(framework.detect_frameworks('x', 't.js'), list)
        self.assertIsInstance(framework.detect_dom_sinks('x', 't.js'), list)
        js_files = [{'url': 't.js', 'content': 'x'}]
        settings = {'JS_RECON_SOURCE_MAPS': True, 'JS_RECON_DEPENDENCY_CHECK': True,
                     'JS_RECON_EXTRACT_ENDPOINTS': True, 'JS_RECON_CUSTOM_SOURCEMAP_PATHS': '',
                     'JS_RECON_CUSTOM_PACKAGES': '', 'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': '',
                     'JS_RECON_TIMEOUT': 900}
        self.assertIsInstance(sourcemap.discover_and_analyze_sourcemaps(js_files, settings), list)
        self.assertIsInstance(dependency.detect_dependency_confusion(js_files, settings), list)
        self.assertIsInstance(endpoints_mod.extract_endpoints(js_files, settings), list)

    def test_comprehensive_scan(self):
        js = '''
        // TODO: remove hardcoded password
        const config = {
            key: "AKIAIOSFODNN7EXAMPLE",
            firebase: "https://prod.firebaseio.com",
        };
        fetch('/api/admin/dashboard');
        new WebSocket('wss://api.target.com/ws');
        element.innerHTML = userInput;
        import { sdk } from '@mycompany/internal-sdk';
        '''
        findings = patterns.scan_js_content(js, 'https://t.com/app.js')
        names = {f['name'] for f in findings}
        self.assertIn('AWS Access Key ID', names)
        self.assertIn('Firebase URL', names)

        eps = endpoints_mod.extract_endpoints(
            [{'url': 'https://t.com/app.js', 'content': js}],
            {'JS_RECON_EXTRACT_ENDPOINTS': True, 'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': ''}
        )
        self.assertTrue(any(e['path'] == '/api/admin/dashboard' for e in eps))

        sinks = framework.detect_dom_sinks(js, 'app.js')
        self.assertTrue(any(s['type'] == 'innerHTML' for s in sinks))

        comments = patterns.scan_dev_comments(js, 'app.js')
        self.assertGreaterEqual(len(comments), 1)

        pkgs = dependency.extract_scoped_packages(js)
        self.assertIn('@mycompany/internal-sdk', pkgs)


if __name__ == '__main__':
    unittest.main(verbosity=2)
