"ISAPI client for Home Assistant integration."

import inspect
import logging
from typing import Any

import httpx

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.util import slugify

from .const import (
    ALARM_SERVER_PATH,
    CONF_ALARM_SERVER_HOST,
    CONF_POLLING_INTERVAL,
    CONF_SET_ALARM_SERVER,
    DOMAIN,
    EVENTS,
    EVENTS_COORDINATOR,
    RTSP_PORT_FORCED,
    SECONDARY_COORDINATOR,
    SECURITY_COORDINATOR,
)
from .coordinator import EventsCoordinator, SecondaryCoordinator, SecurityArmingListener, SecurityCoordinator
from .isapi import (
    EventInfo,
    IPCamera,
    ISAPIClient,
    ISAPIForbiddenError,
    ISAPIUnauthorizedError,
)
from .isapi.const import EVENT_IO

_LOGGER = logging.getLogger(__name__)

# HA deprecated DeviceInfo's "via_device" (identifiers tuple) in favor of "via_device_id"
# (device registry entry id). Support both, since the accepted keyword depends on the
# installed HA core version.
_SUPPORTS_VIA_DEVICE_ID = "via_device_id" in inspect.signature(dr.DeviceRegistry.async_get_or_create).parameters

# HA deprecated DeviceRegistry.async_get_device() (identifiers/connections are no longer
# guaranteed unique across config entries) in favor of async_get_device_by_identifier(),
# which is scoped to a config entry. Support both, since the accepted method depends on
# the installed HA core version.
_SUPPORTS_DEVICE_BY_IDENTIFIER = hasattr(dr.DeviceRegistry, "async_get_device_by_identifier")


class HikvisionDevice(ISAPIClient):
    """Hikvision device for Home Assistant integration."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Initialize device."""

        config = entry.data if entry else data
        self.entry = entry
        self.hass = hass
        self.auth_token_expired = False
        self.control_alarm_server_host = config[CONF_SET_ALARM_SERVER]
        self.alarm_server_host = config[CONF_ALARM_SERVER_HOST]
        self.polling_interval = config.get(CONF_POLLING_INTERVAL)

        # init ISAPI client
        host = config[CONF_HOST]
        username = config[CONF_USERNAME]
        password = config[CONF_PASSWORD]
        verify_ssl = config.get(CONF_VERIFY_SSL, True)
        rtsp_port_forced = config.get(RTSP_PORT_FORCED, None)
        session = get_async_client(hass, verify_ssl)
        super().__init__(host, username, password, verify_ssl, rtsp_port_forced, session)

        self.events_info: list[EventInfo] = []
        self.arming_listener: SecurityArmingListener | None = None

    async def init_coordinators(self):
        """Initialize coordinators."""

        self.coordinators = {}

        if self.device_info.is_security_panel:
            self._init_security_entities()
            self.coordinators[SECURITY_COORDINATOR] = SecurityCoordinator(
                self.hass, self, interval_override=self.polling_interval
            )
            self.arming_listener = SecurityArmingListener(self.hass, self)
            self.arming_listener.async_start()
        else:
            # init events supported by integration
            self.events_info = self.get_device_event_capabilities()
            for camera in self.cameras:
                camera.events_info = self.get_device_event_capabilities(camera.id)

            self.coordinators[EVENTS_COORDINATOR] = EventsCoordinator(
                self.hass, self, interval_override=self.polling_interval
            )

        if self.capabilities.support_holiday_mode or self.capabilities.support_alarm_server or self.storage:
            self.coordinators[SECONDARY_COORDINATOR] = SecondaryCoordinator(self.hass, self)

        if self.control_alarm_server_host and self.capabilities.support_alarm_server:
            await self.set_alarm_server(self.alarm_server_host, ALARM_SERVER_PATH)

        # first data fetch
        for coordinator in self.coordinators.values():
            await coordinator.async_config_entry_first_refresh()

    def _init_security_entities(self):
        """Compute unique_id for each security control panel partition and zone."""
        serial = slugify(self.device_info.serial_no.lower())
        for partition in self.partitions:
            partition.unique_id = f"{serial}_partition_{partition.id}"
        for zone in self.zones:
            zone.unique_id = f"{serial}_zone_{zone.id}"

    def hass_device_info(self, camera_id: int = 0) -> DeviceInfo:
        """Return Home Assistant entity device information."""
        if camera_id == 0:
            return DeviceInfo(
                manufacturer=self.device_info.manufacturer,
                identifiers={(DOMAIN, self.device_info.serial_no)},
                connections={(dr.CONNECTION_NETWORK_MAC, self.device_info.mac_address)},
                model=self.device_info.model,
                name=self.device_info.name,
                sw_version=self.device_info.firmware,
            )
        else:
            camera_info = self.get_camera_by_id(camera_id)
            is_ip_camera = isinstance(camera_info, IPCamera)

            via_device_kwarg = {}
            if self.device_info.is_nvr:
                if _SUPPORTS_VIA_DEVICE_ID:
                    registry = dr.async_get(self.hass)
                    if _SUPPORTS_DEVICE_BY_IDENTIFIER:
                        nvr_device = registry.async_get_device_by_identifier(
                            (DOMAIN, self.device_info.serial_no), self.entry.entry_id
                        )
                    else:
                        nvr_device = registry.async_get_device(identifiers={(DOMAIN, self.device_info.serial_no)})
                    via_device_kwarg["via_device_id"] = nvr_device.id if nvr_device else None
                else:
                    via_device_kwarg["via_device"] = (DOMAIN, self.device_info.serial_no)

            return DeviceInfo(
                manufacturer=self.device_info.manufacturer,
                identifiers={(DOMAIN, camera_info.serial_no)},
                model=camera_info.model,
                name=camera_info.name,
                sw_version=camera_info.firmware if is_ip_camera else "Unknown",
                **via_device_kwarg,
            )

    def get_device_event_capabilities(
        self,
        camera_id: int | None = None,
    ) -> list[EventInfo]:
        """Get events info handled by integration (camera id:  NVR = None, camera > 0)."""

        if camera_id is None:  # NVR
            integration_supported_events = [
                s for s in self.supported_events if (s.id in EVENTS and EVENTS[s.id].get("type") == EVENT_IO)
            ]
        else:  # Camera
            integration_supported_events = [
                s for s in self.supported_events if (s.channel_id == int(camera_id) and s.id in EVENTS)
            ]

        events_by_unique_id: dict[str, EventInfo] = {}
        for event in integration_supported_events:
            if not EVENTS.get(event.id):
                continue

            # Build unique_id
            device_id_param = f"_{camera_id}" if camera_id else ""
            io_port_id_param = f"_{event.io_port_id}" if event.io_port_id != 0 else ""
            unique_id = f"{slugify(self.device_info.serial_no.lower())}{device_id_param}{io_port_id_param}_{event.id}"

            existing = events_by_unique_id.get(unique_id)
            if existing:
                # Different raw ISAPI event types (e.g. VMD + thermometry) can translate to the
                # same synthetic id via EVENTS_ALTERNATE_ID for the same channel. Merge their
                # notifications instead of keeping two EventInfo with the same entity_id, which
                # would otherwise fight over the entity registry's disabled_by flag on every
                # setup and trigger an endless reload loop.
                existing.notifications = list(set(existing.notifications) | set(event.notifications))
                existing.disabled = "center" not in existing.notifications
                continue

            event.unique_id = unique_id
            event.disabled = "center" not in event.notifications  # Disable if not set Notify Surveillance Center
            events_by_unique_id[unique_id] = event

        return list(events_by_unique_id.values())

    def handle_exception(self, ex: Exception, details: str = ""):
        """Handle common exceptions."""

        error = "Unexpected exception"

        if isinstance(ex, ISAPIUnauthorizedError):
            if not self.auth_token_expired:
                # after device reboot, authorization token may have expired
                self.auth_token_expired = True
                self._auth_method = None
                self._session = get_async_client(self.hass, self.verify_ssl)
                _LOGGER.warning("Unauthorized access to %s, started checking if token expired", self.host)
                return
            self.auth_token_expired = False
            self.entry.async_start_reauth(self.hass)
            error = "Unauthorized access"
        elif isinstance(ex, ISAPIForbiddenError):
            error = "Forbidden access"
        elif isinstance(ex, (httpx.TimeoutException, httpx.ConnectTimeout)):
            error = "Timeout"
        elif isinstance(ex, (httpx.ConnectError, httpx.NetworkError)):
            error = "Connection error"

        _LOGGER.warning("%s | %s | %s | %s", error, self.host, details, ex)
