## Installation

### Prerequisites
- Python 3.9 or higher
- Docker (optional for containerized deployment)

### Steps

#### Option 1: Run Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/HTB-Machine-Helper.git
   cd HTB-Machine-Helper
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app:
   ```bash
   streamlit run htb_machine_tracker.py
   ```

4. Open the app in your browser:
   - Default URL: `http://localhost:8501`

#### Option 2: Use Docker
1. Build the Docker image:
   ```bash
   docker build -t htb-machine-helper .
   ```

2. Run the Docker container:
   ```bash
   docker run -d -p 8501:8501 --name htb-helper htb-machine-helper
   ```

3. Access the app:
   - Default URL: `http://<your-machine-ip>:8501`
