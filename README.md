# GeoIPNetworkAnalyzer
# Java Network Analyzer with Geolocation

## Overview
A network packet analyzer built in Java using Pcap4J to capture live traffic and query MaxMind's GeoIP2 database to visualize the geolocation of unique IP packets. This tool filters out duplicate IPs, ensuring only distinct addresses are processed for display.

## Features

- Packet sniffing via Pcap4J
- IP geolocation using MaxMind GeoIP2
- Displays unique external IPs only
- JavaFX-based UI for visualization
- Real-time capture and lookup
- Optional logging of results

## Prerequisites

- Java JDK 11 or higher
- MaxMind GeoIP2 Java API and database file (`GeoLite2-City.mmdb`)
- Pcap4J library
- Internet access for downloading MaxMind DB updates
