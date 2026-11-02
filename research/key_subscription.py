"""Keep key messages queued while the receiver checks its directory identity."""


def subscribed_acquirer_class(protocol):
    class SubscribedAcquirer(protocol.PeopleKeyAcquirer):
        async def _run_receiver_preflight(self, connection, base_token):
            # Upstream calls this before opening the long-lived topic streams.
            # Its temporary directory stream ignores unrelated messages, so a
            # queued key could otherwise be consumed before a key waiter exists.
            self._pending_receiver_preflight = (connection, base_token)

        async def finish_receiver_preflight(self):
            pending = self._pending_receiver_preflight
            self._pending_receiver_preflight = None
            if pending is not None:
                await super()._run_receiver_preflight(*pending)

    return SubscribedAcquirer
