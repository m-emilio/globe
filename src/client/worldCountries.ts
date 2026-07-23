/**
 * Load simplified world country polygons (Natural Earth 110m via world-atlas)
 * and index by ISO 3166-1 alpha-3 for choropleth fills.
 */

import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { Feature, FeatureCollection, Geometry, MultiPolygon, Polygon } from "geojson";

/** Same-origin copy of Natural Earth 110m (avoids CSP connect-src issues). */
const WORLD_ATLAS_URL = "/geo/countries-110m.json";

/** ISO 3166-1 numeric (no leading zeros) → alpha-3 */
const M49_TO_ISO3: Record<string, string> = {
  "4": "AFG",
  "8": "ALB",
  "12": "DZA",
  "20": "AND",
  "24": "AGO",
  "28": "ATG",
  "31": "AZE",
  "32": "ARG",
  "36": "AUS",
  "40": "AUT",
  "44": "BHS",
  "48": "BHR",
  "50": "BGD",
  "51": "ARM",
  "52": "BRB",
  "56": "BEL",
  "64": "BTN",
  "68": "BOL",
  "70": "BIH",
  "72": "BWA",
  "76": "BRA",
  "84": "BLZ",
  "90": "SLB",
  "96": "BRN",
  "100": "BGR",
  "104": "MMR",
  "108": "BDI",
  "112": "BLR",
  "116": "KHM",
  "120": "CMR",
  "124": "CAN",
  "132": "CPV",
  "140": "CAF",
  "144": "LKA",
  "148": "TCD",
  "152": "CHL",
  "156": "CHN",
  "158": "TWN",
  "170": "COL",
  "174": "COM",
  "178": "COG",
  "180": "COD",
  "188": "CRI",
  "191": "HRV",
  "192": "CUB",
  "196": "CYP",
  "203": "CZE",
  "204": "BEN",
  "208": "DNK",
  "212": "DMA",
  "214": "DOM",
  "218": "ECU",
  "222": "SLV",
  "226": "GNQ",
  "231": "ETH",
  "232": "ERI",
  "233": "EST",
  "242": "FJI",
  "246": "FIN",
  "250": "FRA",
  "262": "DJI",
  "266": "GAB",
  "268": "GEO",
  "270": "GMB",
  "275": "PSE",
  "276": "DEU",
  "288": "GHA",
  "300": "GRC",
  "308": "GRD",
  "320": "GTM",
  "324": "GIN",
  "328": "GUY",
  "332": "HTI",
  "340": "HND",
  "348": "HUN",
  "352": "ISL",
  "356": "IND",
  "360": "IDN",
  "364": "IRN",
  "368": "IRQ",
  "372": "IRL",
  "376": "ISR",
  "380": "ITA",
  "384": "CIV",
  "388": "JAM",
  "392": "JPN",
  "398": "KAZ",
  "400": "JOR",
  "404": "KEN",
  "408": "PRK",
  "410": "KOR",
  "414": "KWT",
  "417": "KGZ",
  "418": "LAO",
  "422": "LBN",
  "426": "LSO",
  "428": "LVA",
  "430": "LBR",
  "434": "LBY",
  "440": "LTU",
  "442": "LUX",
  "450": "MDG",
  "454": "MWI",
  "458": "MYS",
  "462": "MDV",
  "466": "MLI",
  "470": "MLT",
  "478": "MRT",
  "480": "MUS",
  "484": "MEX",
  "496": "MNG",
  "498": "MDA",
  "499": "MNE",
  "504": "MAR",
  "508": "MOZ",
  "512": "OMN",
  "516": "NAM",
  "524": "NPL",
  "528": "NLD",
  "540": "NCL",
  "548": "VUT",
  "554": "NZL",
  "558": "NIC",
  "562": "NER",
  "566": "NGA",
  "578": "NOR",
  "583": "FSM",
  "584": "MHL",
  "585": "PLW",
  "586": "PAK",
  "591": "PAN",
  "598": "PNG",
  "600": "PRY",
  "604": "PER",
  "608": "PHL",
  "616": "POL",
  "620": "PRT",
  "624": "GNB",
  "626": "TLS",
  "630": "PRI",
  "634": "QAT",
  "642": "ROU",
  "643": "RUS",
  "646": "RWA",
  "662": "LCA",
  "670": "VCT",
  "678": "STP",
  "682": "SAU",
  "686": "SEN",
  "688": "SRB",
  "690": "SYC",
  "694": "SLE",
  "702": "SGP",
  "703": "SVK",
  "704": "VNM",
  "705": "SVN",
  "706": "SOM",
  "710": "ZAF",
  "716": "ZWE",
  "724": "ESP",
  "728": "SSD",
  "729": "SDN",
  "740": "SUR",
  "748": "SWZ",
  "752": "SWE",
  "756": "CHE",
  "760": "SYR",
  "762": "TJK",
  "764": "THA",
  "768": "TGO",
  "780": "TTO",
  "784": "ARE",
  "788": "TUN",
  "792": "TUR",
  "795": "TKM",
  "800": "UGA",
  "804": "UKR",
  "807": "MKD",
  "818": "EGY",
  "826": "GBR",
  "834": "TZA",
  "840": "USA",
  "854": "BFA",
  "858": "URY",
  "860": "UZB",
  "862": "VEN",
  "887": "YEM",
  "894": "ZMB",
};

export type CountryPolygon = {
  iso3: string;
  name: string;
  /** Exterior rings only: [lng, lat][][] */
  rings: [number, number][][];
};

type WorldTopology = Topology<{
  countries: GeometryCollection;
}>;

let loadPromise: Promise<Map<string, CountryPolygon>> | null = null;
let cache: Map<string, CountryPolygon> | null = null;

function geometryToRings(geometry: Geometry | null | undefined): [number, number][][] {
  if (!geometry) return [];
  if (geometry.type === "Polygon") {
    return (geometry as Polygon).coordinates.map((ring) =>
      ring.map(([lng, lat]) => [lng, lat] as [number, number]),
    );
  }
  if (geometry.type === "MultiPolygon") {
    const rings: [number, number][][] = [];
    for (const poly of (geometry as MultiPolygon).coordinates) {
      // Exterior ring only (index 0) for fill; skip holes for performance
      if (poly[0]) {
        rings.push(poly[0].map(([lng, lat]) => [lng, lat] as [number, number]));
      }
    }
    return rings;
  }
  return [];
}

/**
 * Decimate coastlines for globe overlay projection.
 * 110m data is already coarse; 24–32 pts is enough on a ~400px disc.
 * Higher counts destroy FPS when UNODC reprojects every spin tick.
 */
function simplifyRing(
  ring: [number, number][],
  maxPoints = 28,
): [number, number][] {
  if (ring.length <= maxPoints) return ring;
  const step = Math.ceil(ring.length / maxPoints);
  const out: [number, number][] = [];
  for (let i = 0; i < ring.length; i += step) {
    out.push(ring[i]);
  }
  // Close ring
  const first = out[0];
  const last = out[out.length - 1];
  if (first && last && (first[0] !== last[0] || first[1] !== last[1])) {
    out.push(first);
  }
  return out;
}

/** Keep only the largest exterior rings (main landmasses); skip tiny islands. */
function capRings(
  rings: [number, number][][],
  maxRings = 3,
): [number, number][][] {
  if (rings.length <= maxRings) return rings;
  return [...rings]
    .sort((a, b) => b.length - a.length)
    .slice(0, maxRings);
}

export async function loadCountryPolygons(): Promise<Map<string, CountryPolygon>> {
  if (cache) return cache;
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    const response = await fetch(WORLD_ATLAS_URL, {
      headers: { accept: "application/json" },
      // Static asset — always prefer disk/HTTP cache over re-download.
      cache: "force-cache",
    });
    if (!response.ok) {
      throw new Error(`Failed to load world atlas (${response.status})`);
    }
    const topology = (await response.json()) as WorldTopology;
    const collection = feature(
      topology,
      topology.objects.countries,
    ) as FeatureCollection;

    const map = new Map<string, CountryPolygon>();
    for (const f of collection.features as Feature[]) {
      const rawId = f.id != null ? String(f.id).replace(/^0+/, "") || "0" : "";
      const iso3 = M49_TO_ISO3[rawId];
      if (!iso3) continue;
      const name =
        (f.properties &&
          typeof f.properties === "object" &&
          "name" in f.properties &&
          typeof (f.properties as { name?: string }).name === "string"
          ? (f.properties as { name: string }).name
          : iso3) || iso3;
      const rings = capRings(
        geometryToRings(f.geometry)
          .map((ring) => simplifyRing(ring, 28))
          .filter((ring) => ring.length >= 4),
        3,
      );
      if (rings.length === 0) continue;
      map.set(iso3, { iso3, name, rings });
    }
    cache = map;
    return map;
  })();

  try {
    return await loadPromise;
  } catch (error) {
    loadPromise = null;
    throw error;
  }
}

export function getCachedCountryPolygons(): Map<string, CountryPolygon> | null {
  return cache;
}
