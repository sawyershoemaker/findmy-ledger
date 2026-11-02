import unittest
try:
    from research.account_routes import extract_routes
except ImportError:
    extract_routes = None


@unittest.skipIf(extract_routes is None, "Install the auth extra")
class AccountRouteTests(unittest.TestCase):
    def test_route_discovery_ignores_field_names_and_discards_tokens_and_non_findmy_urls(self):
        from research.account_routes import route_candidates
        expected = {"https://gateway.icloud.com/findmyservice/", "https://p01-fmfmobile.icloud.com/"}
        self.assertEqual(route_candidates({"unknown_bag_wrapper": [
            {"unknown_field": url} for url in expected | {"https://gateway.icloud.com/unrelated/",
            "https://gateway.icloud.com/findmyservice/?private=secret", "https://gateway.icloud.com.evil.invalid/findmyservice/"}],
            "tokens": {"url": "https://gateway.icloud.com/findmyservice/private-token"}}), expected)

    def test_webservice_routes_exclude_other_services_and_credentials(self):
        from research.account_routes import service_map_routes
        services, summary = service_map_routes({"webservices": {
            "Findme": {"url": "https://p01-fmipmobile.icloud.com/", "appHostname": "p01-fmfmobile.icloud.com",
                       "tokens": {"secret": "private"}, "email": "private@example.invalid"},
            "SearchParty": {"url": "https://gateway.icloud.com/findmyservice/"},
            "Contacts": {"url": "https://contacts.example.invalid/"}}})
        self.assertEqual(services, {"Findme": {"url": "https://p01-fmipmobile.icloud.com/",
            "appHostname": "p01-fmfmobile.icloud.com"}, "SearchParty": {"url": "https://gateway.icloud.com/findmyservice/"}})
        self.assertEqual(summary["recognized_services"], ["Findme", "SearchParty"])
        self.assertEqual(summary["findmy_service_route_count"], 3)

    def test_only_native_findmy_routes_are_retained(self):
        routes = {"people_url": "https://p01-fmfmobile.icloud.com/", "secureLocationsServiceURL": "https://gateway.icloud.com/findmyservice/"}
        self.assertEqual(extract_routes({"webservices": {"DeviceLocator": {"people_url": routes["people_url"]},
            "SearchParty": {"secureLocationsServiceURL": routes["secureLocationsServiceURL"]}},
            "tokens": {"secret": "synthetic-token"}, "accountName": "private@example.invalid",
            "unrelated_service": {"url": "https://unrelated.example.invalid"}}), routes)

    def test_credentials_queries_and_unapproved_hosts_are_rejected(self):
        for route in ("http://gateway.icloud.com/findmyservice/", "https://gateway.icloud.com.evil.invalid/",
                      "https://user:password@gateway.icloud.com/", "https://gateway.icloud.com/?token=secret",
                      "https://gateway.icloud.com:123/", "https://gateway.icloud.com/#private", None):
            with self.subTest(route=route), self.assertRaises(ValueError):
                extract_routes({"secureLocationsServiceURL": route})

    def test_conflicting_routes_cannot_silently_replace_the_first(self):
        first = {"people_url": "https://p01-fmfmobile.icloud.com/"}
        second = {"people_url": "https://p02-fmfmobile.icloud.com/"}
        for value in ([first, second], {"nested": first, **second}, {**second, "nested": first}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract_routes(value)
