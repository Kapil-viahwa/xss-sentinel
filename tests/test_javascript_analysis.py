import unittest

from xss_sentinel.javascript_analysis import analyze_javascript


class JavaScriptAnalysisTest(unittest.TestCase):
    def test_finds_literal_and_constant_bound_api_routes(self):
        result = analyze_javascript("const route = '/api/items'; fetch(route); axios.post('/graphql', body);")
        routes = {(item["path"], item["method"]) for item in result["endpoints"]}
        self.assertIn(("/api/items", "GET"), routes)
        self.assertIn(("/graphql", "POST"), routes)

    def test_extracts_json_body_properties_without_values(self):
        source = "fetch('/api/profile', {method: 'POST', body: JSON.stringify({profile: {name: userName}, token: sessionToken})});"
        result = analyze_javascript(source)
        endpoint = next(item for item in result["endpoints"] if item["path"] == "/api/profile")
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual({item["name"] for item in endpoint["inputs"]}, {"profile.name", "token"})
        self.assertTrue(all(item["location"] == "json" for item in endpoint["inputs"]))

    def test_extracts_nested_json_request_properties(self):
        source = "const payload = {profile: {name: userName}, token: sessionToken}; fetch('/api/profile', {method: 'POST', body: JSON.stringify(payload)});"
        endpoint = next(item for item in analyze_javascript(source)["endpoints"] if item["path"] == "/api/profile")
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual({item["name"] for item in endpoint["inputs"]}, {"profile.name", "token"})
        self.assertTrue(all(item["location"] == "json" for item in endpoint["inputs"]))

    def test_records_low_confidence_source_sink_indicators(self):
        source = "function render() { const input = window.location.search; document.getElementById('out').innerHTML = input; }"
        result = analyze_javascript(source)
        self.assertTrue(any(item["source"] == "location.search" and item["sink"] == "innerHTML" for item in result["observations"]))
        self.assertTrue(all(item["confidence"] == "low" for item in result["observations"]))

    def test_analyzes_anonymous_event_handler_callbacks(self):
        source = "window.addEventListener('message', function(event) { document.querySelector('#out').innerHTML = event.data; });"
        observations = analyze_javascript(source)["observations"]
        self.assertTrue(any(
            item["source"] == "postMessage event.data" and item["sink"] == "innerHTML"
            for item in observations
        ))

    def test_traces_taint_through_a_bounded_function_call(self):
        source = "function render(value) { document.getElementById('out').innerHTML = value; } function route() { const input = window.location.search; render(input); }"
        observations = analyze_javascript(source)["observations"]
        self.assertTrue(any(
            item["source"] == "location.search" and item["sink"] == "innerHTML"
            for item in observations
        ))
        self.assertTrue(all(item["confidence"] == "low" for item in observations))

    def test_traces_single_parameter_arrow_function_helpers(self):
        source = "const render = value => { document.querySelector('#out').innerHTML = value; }; function route() { const input = window.name; render(input); }"
        observations = analyze_javascript(source)["observations"]
        self.assertTrue(any(
            item["source"] == "window.name" and item["sink"] == "innerHTML"
            for item in observations
        ))

    def test_traces_local_aliases_to_dom_method_sinks(self):
        source = "function render(value) { const alias = value; document.querySelector('#out').insertAdjacentHTML('beforeend', alias); } function route() { const input = location.hash; render(input); }"
        observations = analyze_javascript(source)["observations"]
        self.assertTrue(any(
            item["source"] == "location.hash" and item["sink"].endswith("insertAdjacentHTML")
            for item in observations
        ))

    def test_non_api_strings_are_not_reported_as_endpoints(self):
        result = analyze_javascript("const label = 'Save changes'; console.log(label);")
        self.assertEqual(result["endpoints"], [])


if __name__ == "__main__":
    unittest.main()
