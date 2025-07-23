package com.example.analyzer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.Pcaps;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.function.Consumer;
import java.util.logging.Logger;

public class PacketCapture {
    private static final Logger LOGGER = Logger.getLogger(PacketCapture.class.getName());
    private static final Set<String> privateIPs = Set.of(
        "10.", "172.", "192.168.", "169.254."  // Add more private IP ranges as needed
    );
    
    private final GeoIP geoIP;
    private final Set<String> processedIPs; // Set to store IPs we've already processed

    public PacketCapture(String geoIPDBPath) throws IOException {
        this.geoIP = new GeoIP(geoIPDBPath);
        this.processedIPs = new HashSet<>(); // Initialize the set
    }

    public void analyzePcap(String pcapFilePath, Supplier<Boolean> shouldStop, Consumer<String> outputCallback) throws IOException {
        try (PcapHandle handle = Pcaps.openOffline(pcapFilePath)) {
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {
                if (shouldStop.get()) {
                    LOGGER.info("Analysis stopped by user.");
                    break;
                }

                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                if (ipPacket != null) {
                    String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                    String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

                    // Look up and output geolocation info for source IP if not processed before
                    if (!isPrivateIP(srcIp) && !processedIPs.contains(srcIp)) {
                        geoIP.lookupIP(srcIp); // Calls GeoIP to perform the lookup
                        outputCallback.accept("Source IP: " + srcIp + " Geolocation: " + geoIP.getGeolocation(srcIp)); // Callback for output
                        processedIPs.add(srcIp); // Mark this IP as processed
                    }

                    // Look up and output geolocation info for destination IP if not processed before
                    if (!isPrivateIP(dstIp) && !processedIPs.contains(dstIp)) {
                        geoIP.lookupIP(dstIp); // Calls GeoIP to perform the lookup
                        outputCallback.accept("Destination IP: " + dstIp + " Geolocation: " + geoIP.getGeolocation(dstIp)); // Callback for output
                        processedIPs.add(dstIp); // Mark this IP as processed
                    }
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            LOGGER.severe("Failed to analyze PCAP file: " + e.getMessage());
        }
    }

    private boolean isPrivateIP(String ip) {
        return privateIPs.stream().anyMatch(ip::startsWith);
    }

    public void close() throws IOException {
        geoIP.close();
    }
}
