package com.example.analyzer;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import com.maxmind.geoip2.model.CityResponse;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GeoIP {
    private static final Logger logger = Logger.getLogger(GeoIP.class.getName());
    private final DatabaseReader reader;
    private static final Set<String> privateIpsLogged = new HashSet<>();

    // Private IP ranges for filtering
    private static final long[][] PRIVATE_IP_RANGES = {
        {ipToLong("10.0.0.0"), ipToLong("10.255.255.255")},
        {ipToLong("172.16.0.0"), ipToLong("172.31.255.255")},
        {ipToLong("192.168.0.0"), ipToLong("192.168.255.255")}
    };

    public GeoIP(String geoipDbPath) throws IOException {
        File database = new File(geoipDbPath);
        reader = new DatabaseReader.Builder(database).build();
    }

    /**
     * Checks if an IP is private based on known private IP ranges.
     */
    private boolean isPrivateIP(String ip) {
        long ipLong = ipToLong(ip);
        for (long[] range : PRIVATE_IP_RANGES) {
            if (ipLong >= range[0] && ipLong <= range[1]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Converts an IP address to a long for easier range checking.
     */
    private static long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        return (Long.parseLong(octets[0]) << 24) |
               (Long.parseLong(octets[1]) << 16) |
               (Long.parseLong(octets[2]) << 8) |
               Long.parseLong(octets[3]);
    }

    /**
     * Perform a GeoIP lookup for a given IP address, ignoring private and invalid IPs.
     */
    public void lookupIP(String ip) {
        if (isPrivateIP(ip)) {
            return; // Skip private IPs
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            CityResponse response = reader.city(inetAddress);
            Country country = response.getCountry();
            City city = response.getCity();
            Location location = response.getLocation();

            logger.info("[*] Target: " + ip + " Geo Located.");
            logger.info("[+] Country: " + country.getName() + 
                        ", City: " + city.getName() +
                        ", Latitude: " + location.getLatitude() +
                        ", Longitude: " + location.getLongitude());
        } catch (AddressNotFoundException e) {
            logger.warning("GeoIP lookup failed for IP: " + ip);
        } catch (GeoIp2Exception | IOException e) {
            logger.log(Level.SEVERE, "GeoIP lookup error for IP: " + ip, e);
        }
    }

    /**
     * Get the geolocation details for a given IP as a formatted string
     */
    public String getGeolocation(String ip) {
        if (isPrivateIP(ip)) {
            return "Private IP: " + ip; // Return message for private IPs
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            CityResponse response = reader.city(inetAddress);
            Country country = response.getCountry();
            City city = response.getCity();
            Location location = response.getLocation();

            // Return a formatted string with geolocation info
            return String.format("Country: %s, City: %s, Latitude: %f, Longitude: %f",
                                 country.getName(), city.getName(), location.getLatitude(), location.getLongitude());
        } catch (AddressNotFoundException e) {
            logger.warning("GeoIP lookup failed for IP: " + ip);
            return "GeoIP lookup failed for IP: " + ip;
        } catch (GeoIp2Exception | IOException e) {
            logger.log(Level.SEVERE, "GeoIP lookup error for IP: " + ip, e);
            return "GeoIP lookup error for IP: " + ip;
        }
    }

    public void close() {
        try {
            reader.close();
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error closing GeoIP database reader", e);
        }
    }
}
