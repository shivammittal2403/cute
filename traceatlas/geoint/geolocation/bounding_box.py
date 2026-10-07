"""traceatlas.geoint.geolocation.bounding_box - BBox primitives + geometry."""
from __future__ import annotations

from dataclasses import dataclass

from traceatlas.geoint.geolocation.coordinate_parser import LatLng
from traceatlas.geoint.geolocation.distance import meters_to_deg_lat, meters_to_deg_lon


@dataclass(frozen=True, slots=True)
class BoundingBox:
    """Axis-aligned lat/lon box (west,south,east,north ordering internally)."""
    west: float
    south: float
    east: float
    north: float

    def contains(self, pt: LatLng) -> bool:
        return self.south <= pt.lat <= self.north and self.west <= pt.lon <= self.east

    def intersects(self, other: "BoundingBox") -> bool:
        return not (other.west > self.east or other.east < self.west
                    or other.south > self.north or other.north < self.south)

    def center(self) -> LatLng:
        return LatLng(lat=(self.south + self.north) / 2.0,
                      lon=(self.west + self.east) / 2.0)

    @classmethod
    def around(cls, pt: LatLng, radius_m: float) -> "BoundingBox":
        dlat = meters_to_deg_lat(radius_m)
        dlon = meters_to_deg_lon(radius_m, pt.lat)
        return cls(west=pt.lon - dlon, south=pt.lat - dlat,
                   east=pt.lon + dlon, north=pt.lat + dlat)

    @classmethod
    def from_points(cls, pts: list[LatLng]) -> "BoundingBox":
        if not pts:
            raise ValueError("cannot build bbox from empty point list")
        return cls(west=min(p.lon for p in pts), east=max(p.lon for p in pts),
                   south=min(p.lat for p in pts), north=max(p.lat for p in pts))

    def to_geojson_polygon(self) -> dict:
        ring = [[self.west, self.south], [self.east, self.south],
                [self.east, self.north], [self.west, self.north],
                [self.west, self.south]]
        return {"type": "Polygon", "coordinates": [ring]}

    def to_dict(self) -> dict:
        return {"west": self.west, "south": self.south,
                "east": self.east, "north": self.north}

    @classmethod
    def from_dict(cls, d: dict) -> "BoundingBox":
        return cls(west=float(d["west"]), south=float(d["south"]),
                   east=float(d["east"]), north=float(d["north"]))
