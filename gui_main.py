# gui_main.py
# Import necessary libraries for GUI, file operations, system operations, and threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import sys
import threading
import time

# Add the Extract module path to system path for importing custom modules
sys.path.append('Extract')
from Extract.PE_main import extract_infos  # Import function to extract PE file information
import joblib  # For loading machine learning models
import pickle  # For loading serialized feature lists


class SimpleGUI:
    """
    Main GUI class for the Malware Detection System
    Provides a user-friendly interface for malware detection using machine learning
    """
    
    def __init__(self):
        """
        Initialize the GUI application and load the machine learning model
        """
        # Create main window
        self.root = tk.Tk()
        self.root.title("Malware Detector")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # Load pre-trained machine learning model and feature list
        try:
            # Load the trained classifier model
            self.clf = joblib.load('Classifier/classifier.pkl')
            # Load the feature names used during training
            self.features = pickle.loads(open('Classifier/features.pkl', 'rb').read())
            self.model_status = "Model loaded successfully"
        except Exception as e:
            # Handle model loading failure
            self.model_status = f"Model loading failed: {e}"
            self.clf = None

        # Create and arrange GUI components
        self.create_widgets()

    def create_widgets(self):
        """
        Create and arrange all GUI widgets (buttons, labels, text areas, etc.)
        """
        # Main title label
        title = tk.Label(self.root, text="Malware Detection System", font=("Arial", 16, "bold"))
        title.pack(pady=20)

        # Display model loading status
        status_label = tk.Label(self.root, text=self.model_status, fg="green" if self.clf else "red")
        status_label.pack(pady=5)

        # File selection section
        file_frame = tk.Frame(self.root)
        file_frame.pack(pady=20)

        # Label for file selection
        tk.Label(file_frame, text="Select PE file:").pack()

        # Entry field to display selected file path
        self.file_path = tk.StringVar(value="No file selected")
        file_entry = tk.Entry(file_frame, textvariable=self.file_path, width=50, state="readonly")
        file_entry.pack(pady=5)

        # Browse button to open file dialog
        select_btn = tk.Button(file_frame, text="Browse", command=self.select_file)
        select_btn.pack(pady=5)

        # Detection button (initially disabled)
        self.detect_btn = tk.Button(
            self.root,
            text="Start Detection",
            command=self.detect_file,
            bg="green",
            fg="white",
            font=("Arial", 12, "bold"),
            state="disabled"
        )
        self.detect_btn.pack(pady=20)

        # Progress bar to show detection progress
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=10, padx=50, fill="x")

        # Result display section
        result_frame = tk.Frame(self.root)
        result_frame.pack(pady=20, fill="both", expand=True)

        # Label for result section
        tk.Label(result_frame, text="Detection Result:", font=("Arial", 12, "bold")).pack()

        # Text area to display detection results
        self.result_text = tk.Text(result_frame, height=8, width=60)
        self.result_text.pack(pady=5)

        # Exit button at the bottom
        quit_btn = tk.Button(self.root, text="Exit", command=self.root.quit)
        quit_btn.pack(side="bottom", pady=10)

    def select_file(self):
        """
        Open file dialog to allow user to select a PE file for analysis
        """
        filename = filedialog.askopenfilename(
            title="Select PE file",
            filetypes=[
                ("PE files", "*.exe *.dll *.sys"),  # PE file extensions
                ("All files", "*.*")  # Allow all file types as fallback
            ]
        )
        # Update file path and enable detection button if file is selected and model is loaded
        if filename:
            self.file_path.set(filename)
            self.detect_btn.config(state="normal" if self.clf else "disabled")

    def detect_file(self):
        """
        Initiate malware detection process for the selected file
        Runs detection in a separate thread to prevent GUI freezing
        """
        # Check if model is loaded
        if not self.clf:
            messagebox.showerror("Error", "Model not loaded")
            return

        # Check if file is selected
        file_path = self.file_path.get()
        if file_path == "No file selected":
            messagebox.showwarning("Warning", "Please select a file")
            return

        # Prepare UI for detection process
        self.detect_btn.config(state="disabled")  # Disable button during detection
        self.progress.start()  # Start progress bar animation
        self.result_text.delete(1.0, tk.END)  # Clear previous results
        self.result_text.insert(tk.END, "Detecting, please wait...\n")

        # Start detection in a separate thread to keep GUI responsive
        thread = threading.Thread(target=self.run_detection, args=(file_path,))
        thread.daemon = True  # Thread will exit when main program exits
        thread.start()

    def run_detection(self, file_path):
        """
        Execute the actual malware detection process
        This method runs in a separate thread
        
        Args:
            file_path (str): Path to the file to be analyzed
        """
        try:
            start_time = time.time()

            # Extract features from the PE file using existing detection code
            data = extract_infos(file_path)
            # Map extracted data to feature vector expected by the model
            pe_features = list(map(lambda x: data.get(x, 0), self.features))
            # Make prediction using the trained classifier
            res = self.clf.predict([pe_features])[0]
            # Get prediction probabilities for confidence calculation
            prob = self.clf.predict_proba([pe_features])[0]

            end_time = time.time()

            # Interpret results
            result = 'Legitimate file' if res == 1 else 'Malware'
            confidence = max(prob) * 100  # Convert to percentage

            # Update UI with results (must be done on main thread)
            self.root.after(0, self.show_result, file_path, result, confidence, end_time - start_time)

        except Exception as e:
            # Handle any errors during detection
            self.root.after(0, self.show_error, str(e))

    def show_result(self, file_path, result, confidence, analysis_time):
        """
        Display detection results in the GUI
        
        Args:
            file_path (str): Path of the analyzed file
            result (str): Detection result ('Legitimate file' or 'Malware')
            confidence (float): Confidence percentage of the prediction
            analysis_time (float): Time taken for analysis in seconds
        """
        # Stop progress bar and re-enable detection button
        self.progress.stop()
        self.detect_btn.config(state="normal")

        # Clear previous results and display new results
        self.result_text.delete(1.0, tk.END)

        # Format result text with file information and analysis details
        result_text = f"""Detection complete!

File: {os.path.basename(file_path)}
Result: {result}
Confidence: {confidence:.1f}%
Analysis time: {analysis_time:.2f} seconds

{'-' * 40}
"""

        self.result_text.insert(tk.END, result_text)

        # Show popup with detection result
        messagebox.showinfo("Detection Result",
                            f"File: {os.path.basename(file_path)}\nResult: {result}\nConfidence: {confidence:.1f}%")

    def show_error(self, error):
        """
        Display error message when detection fails
        
        Args:
            error (str): Error message to display
        """
        # Stop progress bar and re-enable detection button
        self.progress.stop()
        self.detect_btn.config(state="normal")
        
        # Display error in result text area
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Detection failed: {error}")
        
        # Show error popup
        messagebox.showerror("Error", f"Detection failed: {error}")

    def run(self):
        """
        Start the GUI main event loop
        """
        self.root.mainloop()


# Main program entry point
if __name__ == "__main__":
    # Create and run the GUI application
    app = SimpleGUI()
    app.run()