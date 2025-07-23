package com.example.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.function.Supplier;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NetworkAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(NetworkAnalyzer.class.getName());

    public static void main(String[] args) {
        if (args.length != 2) {
            LOGGER.severe("Usage: java NetworkAnalyzer <path_to_pcap> <path_to_geolite_db>");
            return;
        }

        String pcapFilePath = args[0];
        String geoIPDBPath = args[1];

        // Define the stop condition (e.g., whether the user wants to stop)
        Supplier<Boolean> shouldStop = () -> false; // Adjust this as necessary

        // Call the analyze method with stop condition and output callback
        analyze(pcapFilePath, geoIPDBPath, shouldStop, System.out::println); // Using System.out.println as a placeholder
    }

    // Updated analyze method that accepts Supplier<Boolean> for stop condition and a Consumer<String> for real-time output
    public static void analyze(String pcapFilePath, String geoIPDBPath, Supplier<Boolean> shouldStop, Consumer<String> outputCallback) {
        analyzeWithStopCondition(pcapFilePath, geoIPDBPath, shouldStop, outputCallback);
    }

    public static void analyzeWithStopCondition(String pcapFilePath, String geoIPDBPath, Supplier<Boolean> shouldStop, Consumer<String> outputCallback) {
        try {
            File pcapFile = new File(pcapFilePath);
            File geoipDatabase = new File(geoIPDBPath);

            if (!pcapFile.exists()) {
                LOGGER.log(Level.SEVERE, "PCAP file does not exist: " + pcapFilePath);
                return;
            }

            if (!geoipDatabase.exists()) {
                LOGGER.log(Level.SEVERE, "GeoIP database file does not exist: " + geoIPDBPath);
                return;
            }

            LOGGER.info("Starting analysis...");
            PacketCapture packetCapture = new PacketCapture(geoIPDBPath);
            packetCapture.analyzePcap(pcapFilePath, shouldStop, outputCallback);  // Pass stop condition and callback here
            packetCapture.close();
            LOGGER.info("Analysis completed.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error during network analysis: " + e.getMessage(), e);
        }
    }
}
