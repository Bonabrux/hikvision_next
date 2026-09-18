"""Platform for binary sensor integration."""

from __future__ import annotations

from homeassistant.components.binary_sensor import ENTITY_ID_FORMAT, BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from . import HikvisionConfigEntry
from .const import EVENTS, SECURITY_COORDINATOR, SECURITY_HOST_STATUS, ZONE_DEVICE_CLASS
from .hikvision_device import HikvisionDevice
from .isapi import EventInfo, Zone
from .isapi.const import EVENT_IO


async def async_setup_entry(
    hass: HomeAssistant,
    entry: HikvisionConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add binary sensors for hikvision events states."""

    device = entry.runtime_data

    entities = []

    # Video Events
    for camera in device.cameras:
        for event in camera.events_info:
            entities.append(EventBinarySensor(device, camera.id, event))

    # General Events
    for event in device.events_info:
        entities.append(EventBinarySensor(device, 0, event))

    # Security control panel zones and host-level status
    coordinator = device.coordinators.get(SECURITY_COORDINATOR)
    for zone in device.zones:
        entities.append(ZoneBinarySensor(device, zone, coordinator))
    if coordinator and device.device_info.is_security_panel:
        entities.append(PanelACPowerSensor(device, coordinator))
        entities.append(PanelTamperSensor(device, coordinator))

    async_add_entities(entities)


class EventBinarySensor(BinarySensorEntity):
    """Event detection sensor."""

    _attr_has_entity_name = True
    _attr_is_on = False

    def __init__(self, device: HikvisionDevice, device_id: int, event: EventInfo) -> None:
        """Initialize."""
        self.entity_id = ENTITY_ID_FORMAT.format(event.unique_id)
        self._attr_unique_id = self.entity_id
        self._attr_translation_key = event.id
        if event.id == EVENT_IO:
            self._attr_translation_placeholders = {"io_port_id": event.io_port_id}
        self._attr_device_class = EVENTS[event.id]["device_class"]
        self._attr_device_info = device.hass_device_info(device_id)
        self._attr_entity_registry_enabled_default = not event.disabled


class ZoneBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Security control panel zone sensor."""

    _attr_has_entity_name = True

    def __init__(self, device: HikvisionDevice, zone: Zone, coordinator) -> None:
        """Initialize."""
        super().__init__(coordinator)
        self.entity_id = ENTITY_ID_FORMAT.format(zone.unique_id)
        self._attr_unique_id = self.entity_id
        self._attr_name = zone.name
        self._attr_device_class = ZONE_DEVICE_CLASS.get(zone.detector_type, BinarySensorDeviceClass.SAFETY)
        self._attr_device_info = device.hass_device_info()
        self.zone = zone

    @property
    def is_on(self) -> bool | None:
        """Return True if the zone is triggered (or, for door/window zones, open)."""
        data = self.coordinator.data.get(self.unique_id)
        return bool(data) and data.get("triggered", False)

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        data = self.coordinator.data.get(self.unique_id) or {}
        return {
            "status": data.get("status"),
            "bypassed": data.get("bypassed"),
            "tamper_evident": data.get("tamper_evident"),
            "battery_low": data.get("charge") == "lowPower",
            "magnet_open_status": data.get("magnet_open_status"),
        }


class PanelHostStatusBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Base class for a security control panel's host-level status (not tied to any zone)."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _data_key: str = None

    def __init__(self, device: HikvisionDevice, coordinator, name_suffix: str) -> None:
        """Initialize."""
        super().__init__(coordinator)
        unique_id = f"{device.device_info.serial_no}_{name_suffix}"
        self.entity_id = ENTITY_ID_FORMAT.format(slugify(unique_id))
        self._attr_unique_id = self.entity_id
        self._attr_device_info = device.hass_device_info()
        self._attr_translation_key = f"panel_{name_suffix}"

    @property
    def is_on(self) -> bool | None:
        """Return the host status value for this sensor."""
        data = self.coordinator.data.get(SECURITY_HOST_STATUS)
        return data.get(self._data_key) if data else None


class PanelACPowerSensor(PanelHostStatusBinarySensor):
    """Whether the panel's mains (AC) power is connected."""

    _attr_device_class = BinarySensorDeviceClass.POWER
    _data_key = "ac_connected"

    def __init__(self, device: HikvisionDevice, coordinator) -> None:
        """Initialize."""
        super().__init__(device, coordinator, "ac_power")


class PanelTamperSensor(PanelHostStatusBinarySensor):
    """Whether the panel's own case/cover is open (tamper)."""

    _attr_device_class = BinarySensorDeviceClass.TAMPER
    _data_key = "tamper_evident"

    def __init__(self, device: HikvisionDevice, coordinator) -> None:
        """Initialize."""
        super().__init__(device, coordinator, "tamper")
