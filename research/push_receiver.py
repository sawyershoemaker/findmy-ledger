"""One verified APNs connection, bounded queues, and no reconnect or retries."""
import asyncio
import hashlib
import hmac
from collections import deque
from contextlib import asynccontextmanager

from .apns_probe import connect


class NotificationStream:
    def __init__(self, queue):
        self.queue = queue

    async def receive(self):
        result = await self.queue.get()
        if isinstance(result, BaseException):
            raise result
        return result


class Receiver:
    def __init__(self, commands, token, *, stats=None):
        self.commands, self.token = commands, token
        self.subscriptions = {}
        self.send_lock = asyncio.Lock()
        self.ack_lock = asyncio.Lock()
        self.acknowledged = deque(maxlen=512)
        self.failure = None
        self.stats = stats if stats is not None else {}

    def count(self, name):
        self.stats[name] = self.stats.get(name, 0) + 1

    @property
    async def base_token(self):
        return self.token

    async def _send(self, command):
        if self.failure:
            raise self.failure
        async with self.send_lock:
            await self.commands.send(command)

    async def filters(self):
        from pypush.apns.protocol import FilterCommand
        await self._send(FilterCommand(token=self.token, enabled_topic_hashes=[
            hashlib.sha1(topic.encode()).digest() for topic in self.subscriptions]))

    @asynccontextmanager
    async def notification_stream(self, topic, token=None):
        from pypush.apns.protocol import ADD_KNOWN_TOPIC
        if token is not None and not hmac.compare_digest(token, self.token):
            raise ValueError("Notification token differs from registered identity")
        if self.failure:
            raise self.failure
        ADD_KNOWN_TOPIC(topic)
        queue = asyncio.Queue(maxsize=256)
        self.subscriptions.setdefault(topic, []).append(queue)
        try:
            await self.filters()
            yield NotificationStream(queue)
        finally:
            self.subscriptions[topic].remove(queue)
            if not self.subscriptions[topic]:
                del self.subscriptions[topic]
            if not self.failure:
                await self.filters()

    async def ack(self, command, status=0, *, transport_delivery=False):
        from pypush.apns.protocol import SendMessageAck
        if command.token != self.token:
            raise ValueError("Cannot acknowledge another push identity")
        marker = (command.id, status)
        async with self.ack_lock:
            if not transport_delivery and marker in self.acknowledged:
                return
            await self._send(SendMessageAck(status=status, token=command.token, id=command.id))
            self.acknowledged.append(marker)
            self.count("transport_acks")

    def fail(self, error):
        self.failure = error
        for queues in self.subscriptions.values():
            for queue in queues:
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(error)

    async def pump(self):
        from pypush.apns.protocol import SendMessageCommand
        try:
            while True:
                command = await self.commands.receive()
                self.count("packets_received")
                if not isinstance(command, SendMessageCommand):
                    self.count("control_packets")
                    continue
                self.count("notification_packets")
                if command.token != self.token:
                    self.count("notifications_for_other_token")
                    continue
                if len(command.payload) > 1024 * 1024:
                    raise ValueError("Push payload exceeds the probe limit")
                queues = self.subscriptions.get(command.topic, [])
                if not queues:
                    self.count("notifications_without_subscription")
                for queue in queues:
                    queue.put_nowait(command)
                    self.count("notifications_queued")
                # APNs acknowledges receipt independently of IDS authenticity.
                # Unhandled notifications must not remain unacknowledged; the
                # application still verifies the sender/signature before saving
                # a key or sending its separate IDS application acknowledgement.
                await self.ack(command, transport_delivery=True)
        except Exception as error:
            self.fail(error)

    async def keepalive(self):
        from pypush.apns.protocol import KeepAliveCommand
        try:
            while True:
                await asyncio.sleep(25)
                await self._send(KeepAliveCommand())
        except Exception as error:
            self.fail(error)


@asynccontextmanager
async def verified_connection(certificate, private_key, token=None, *, stats=None):
    async with asyncio.timeout(30):
        commands, actual = await connect(certificate, private_key, token)
    if token is None or not hmac.compare_digest(actual, token):
        await commands.aclose()
        raise ValueError("Push token changed; device registration must be refreshed")
    receiver = Receiver(commands, actual, stats=stats)
    tasks = [asyncio.create_task(receiver.pump()), asyncio.create_task(receiver.keepalive())]
    try:
        yield receiver
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await commands.aclose()
