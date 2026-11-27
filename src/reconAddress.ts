import ipaddr from "ipaddr.js";

export type ReconAddress = {
  value: string;
  family: 4 | 6;
  isPublic: boolean;
  reverseName: string;
};

const globalIpv6 = ipaddr.IPv6.parse("2000::");

export function parseReconAddress(input: string): ReconAddress | null {
  const value = input.trim();
  if (value.length > 45 || !/^[0-9a-f:.]+$/i.test(value)) return null;
  if (!value.includes(":") && !ipaddr.IPv4.isValidFourPartDecimal(value)) return null;
  try {
    const address = ipaddr.parse(value);
    const bytes = address.toByteArray();
    if (address instanceof ipaddr.IPv4) {
      return {
        value: address.toString(), family: 4, isPublic: address.range() === "unicast",
        reverseName: bytes.reverse().join(".") + ".in-addr.arpa",
      };
    }
    return {
      value: address.toString(), family: 6,
      isPublic: address.range() === "unicast" && address.match(globalIpv6, 3),
      reverseName: bytes.map(byte => byte.toString(16).padStart(2, "0")).join("")
        .split("").reverse().join(".") + ".ip6.arpa",
    };
  } catch {
    return null;
  }
}
