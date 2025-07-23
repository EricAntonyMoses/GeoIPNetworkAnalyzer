package com.example.analyzer;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class NetworkAnalyzerGUI extends Application {

    @FXML
    private TextField geoIPTextField;
    @FXML
    private TextField pcapTextField;
    @FXML
    private TextArea outputTextArea;
    @FXML
    private Button startButton;
    @FXML
    private Button terminateButton;
    @FXML
    private Button browseGeoIPButton;
    @FXML
    private Button browsePcapButton;

    private boolean isAnalyzing = false;

    @Override
    public void start(Stage primaryStage) {
        geoIPTextField = new TextField();
        pcapTextField = new TextField();
        outputTextArea = new TextArea();
        startButton = new Button("Start Analysis");
        terminateButton = new Button("Terminate");
        browseGeoIPButton = new Button("Browse GeoIP DB");
        browsePcapButton = new Button("Browse PCAP File");

        startButton.setOnAction(event -> startAnalysis());
        terminateButton.setOnAction(event -> stopAnalysis());

        browseGeoIPButton.setOnAction(event -> browseGeoIPFile());
        browsePcapButton.setOnAction(event -> browsePcapFile());

        VBox root = new VBox(10, geoIPTextField, browseGeoIPButton, pcapTextField, browsePcapButton, startButton, terminateButton, outputTextArea);

        Scene scene = new Scene(root, 800, 600);
        primaryStage.setTitle("Network Analyzer");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void browseGeoIPFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("GeoIP Database", "*.mmdb"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            geoIPTextField.setText(file.getAbsolutePath());
        }
    }

    private void browsePcapFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PCAP Files", "*.pcap"));
        File file = fileChooser.showOpenDialog(null);
        if (file != null) {
            pcapTextField.setText(file.getAbsolutePath());
        }
    }

    private void startAnalysis() {
        if (isAnalyzing) return;

        String geoIPPath = geoIPTextField.getText();
        String pcapPath = pcapTextField.getText();

        if (geoIPPath.isEmpty() || pcapPath.isEmpty()) {
            outputTextArea.appendText("Please provide both GeoIP and PCAP file paths.\n");
            return;
        }

        isAnalyzing = true;

        // Set up stop condition (e.g., stop when the user presses "terminate")
        Supplier<Boolean> shouldStop = () -> !isAnalyzing;

        // Set up the real-time output callback
        Consumer<String> outputCallback = message -> {
            Platform.runLater(() -> {
                outputTextArea.appendText(message + "\n");
                outputTextArea.setScrollTop(Double.MAX_VALUE); // Auto-scroll to the bottom
            });
        };

        // Use Task to run the analysis in a background thread
        Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                try {
                    NetworkAnalyzer.analyze(pcapPath, geoIPPath, shouldStop, outputCallback);
                } catch (Exception e) {
                    Platform.runLater(() -> outputTextArea.appendText("Error: " + e.getMessage() + "\n"));
                }
                return null;
            }
        };

        // Start the task on a separate thread
        Thread analysisThread = new Thread(task);
        analysisThread.setDaemon(true);
        analysisThread.start();
    }

    private void stopAnalysis() {
        isAnalyzing = false;
        outputTextArea.appendText("Analysis stopped.\n");
    }

    public static void main(String[] args) {
        launch(args); // Launch the JavaFX application
    }
}
