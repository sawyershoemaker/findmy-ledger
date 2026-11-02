"""Version-pinned account hooks, keeping credentials inside the local process."""


def make_account(provider, trace):
    from findmy import AsyncAppleAccount
    from .auth_transport import AuthenticationSession

    class DiagnosticSession(AuthenticationSession):
        async def request(self, method, url, **kwargs):
            if hasattr(provider, "mobileme_client"):
                # Keep the provisioned platform consistent in every service request.
                headers = {k: v for k, v in kwargs.get("headers", {}).items() if k.lower() != "x-mme-client-info"}
                service = url == AsyncAppleAccount._ENDPOINT_LOGIN_MOBILEME
                headers["X-Mme-Client-Info"] = provider.mobileme_client if service else provider.client
                if service:
                    headers["User-Agent"] = "com.apple.iCloudHelper/282 CFNetwork/1404.0.5 Darwin/22.2.0"
                elif url == AsyncAppleAccount._ENDPOINT_GSA:
                    headers["User-Agent"] = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.2.0"
                kwargs["headers"] = headers
            response = await super().request(method, url, **kwargs)
            trace.http_response(response.status_code)
            if trace.phase == "apple_service_login" and response.ok:
                try:
                    trace.service_response(response.plist())
                except (ValueError, TypeError, KeyError):
                    pass  # Let the upstream parser handle the actual response.
            return response

    class BootstrapAccount(AsyncAppleAccount):
        bootstrap = None

        def __init__(self, anisette):
            super().__init__(anisette)
            if hasattr(anisette, "account_ids"):
                self._uid = anisette.account_ids["uid"]
                self._devid = anisette.account_ids["devid"]
            # The parent's lazy HTTP session has not opened any connections.
            self._http = DiagnosticSession(trace)

        async def _gsa_request(self, parameters):
            operation = parameters.get("o")
            trace.enter("gsa_init" if operation == "init" else "gsa_complete" if operation == "complete" else "account_login")
            response = await super()._gsa_request(parameters)
            trace.gsa_response(response)
            status = response.get("Status", {})
            if (operation == "complete" and status.get("ec") == 0 and status.get("hsc") == 409
                    and not status.get("au")):
                # Current Apple replies can signal 2FA with hsc=409 and omit au.
                status["au"] = "trustedDeviceSecondaryAuth"
            return response

        async def get_2fa_methods(self):
            if self._account_info and self._account_info.get("trusted_device_2fa"):
                # The optional SMS enumeration endpoint can reject an otherwise
                # valid trusted-device flow. Avoid it when that method is known.
                from findmy import AsyncTrustedDeviceSecondFactor
                return [AsyncTrustedDeviceSecondFactor(self)]
            return await super().get_2fa_methods()

        async def _login_mobileme(self):
            trace.enter("apple_service_login")
            # FindMy.py 0.10.2 discards this state during the MobileMe transition.
            # Keep it only for the DPAPI-encrypted snapshot needed by a future IDS stage.
            self.bootstrap = {key: self._login_state_data.get(key)
                              for key in ("adsid", "idms_pet")}
            return await super()._login_mobileme()

    return BootstrapAccount(provider)
