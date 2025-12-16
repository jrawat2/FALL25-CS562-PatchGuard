"""
Download and prepare Kaggle vulnerability dataset
This script downloads CVEfixes dataset and prepares 500 samples for evaluation.
"""

import os
import subprocess
import json
import pandas as pd
from pathlib import Path

def download_cvefixes_dataset():
    """
    Download CVEfixes dataset from Kaggle.
    Requires Kaggle API credentials to be configured.
    """
    print("Downloading CVEfixes dataset from Kaggle...")

    # Check if kaggle is installed
    try:
        subprocess.run(["kaggle", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: Kaggle CLI not found.")
        print("Install it with: pip install kaggle")
        print("Then configure credentials: https://www.kaggle.com/docs/api")
        return False

    # Download dataset
    try:
        dataset_name = "girish17019/cvefixes-vulnerable-and-fixed-code"
        subprocess.run(
            ["kaggle", "datasets", "download", "-d", dataset_name, "-p", "data/"],
            check=True
        )
        print("Dataset downloaded successfully!")

        # Unzip if needed
        import zipfile
        zip_path = Path("data/cvefixes-vulnerable-and-fixed-code.zip")
        if zip_path.exists():
            print("Extracting dataset...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("data/")
            zip_path.unlink()  # Remove zip file
            print("Extraction complete!")

        return True

    except subprocess.CalledProcessError as e:
        print(f"Error downloading dataset: {e}")
        return False

def prepare_500_samples():
    """
    Extract 500 samples from the dataset for evaluation.
    Focuses on Python vulnerabilities for consistency.
    """
    print("\nPreparing 500 samples for evaluation...")

    # Look for CSV files in data directory
    data_dir = Path("data/")
    csv_files = list(data_dir.glob("*.csv"))

    if not csv_files:
        print("No CSV files found. Check the dataset structure.")
        return

    print(f"Found CSV files: {[f.name for f in csv_files]}")

    # Try to load the main dataset
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            print(f"\nLoaded {csv_file.name}: {len(df)} rows")
            print(f"Columns: {list(df.columns)}")

            # Filter for Python files if language column exists
            if 'language' in df.columns or 'file_extension' in df.columns:
                lang_col = 'language' if 'language' in df.columns else 'file_extension'
                df_python = df[df[lang_col].str.lower().str.contains('py|python', na=False)]
                print(f"Python samples: {len(df_python)}")
            else:
                df_python = df

            # Take 500 samples
            samples = df_python.head(500)

            # Save to JSON for easy loading
            output_file = data_dir / "evaluation_samples_500.json"
            samples.to_json(output_file, orient='records', indent=2)
            print(f"\nSaved 500 samples to: {output_file}")

            # Also save as CSV
            csv_output = data_dir / "evaluation_samples_500.csv"
            samples.to_csv(csv_output, index=False)
            print(f"Saved 500 samples to: {csv_output}")

            return

        except Exception as e:
            print(f"Error processing {csv_file.name}: {e}")
            continue

    print("Could not prepare samples from any CSV file.")

def create_manual_dataset():
    """
    Create a small manual dataset if Kaggle download fails.
    This creates sample vulnerable code snippets for testing.
    """
    print("\nCreating manual test dataset (50 samples)...")

    samples = []

    # SQL Injection examples
    for i in range(10):
        samples.append({
            "id": f"sql_{i}",
            "language": "python",
            "vulnerability_type": "CWE-89: SQL Injection",
            "vulnerable_code": f"""def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return db.execute(query)""",
            "fixed_code": f"""def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))""",
            "description": "SQL injection through string concatenation"
        })

    # XSS examples
    for i in range(10):
        samples.append({
            "id": f"xss_{i}",
            "language": "python",
            "vulnerability_type": "CWE-79: XSS",
            "vulnerable_code": f"""def render_comment(comment):
    return f"<div>{{comment}}</div>" """,
            "fixed_code": f"""import html
def render_comment(comment):
    return f"<div>{{html.escape(comment)}}</div>" """,
            "description": "XSS through unescaped user input"
        })

    # Command Injection examples
    for i in range(10):
        samples.append({
            "id": f"cmd_{i}",
            "language": "python",
            "vulnerability_type": "CWE-78: Command Injection",
            "vulnerable_code": f"""def backup_file(filename):
    os.system(f"tar -czf backup.tar.gz {{filename}}")""",
            "fixed_code": f"""import subprocess
def backup_file(filename):
    subprocess.run(["tar", "-czf", "backup.tar.gz", filename], check=True)""",
            "description": "Command injection through os.system"
        })

    # Path Traversal examples
    for i in range(10):
        samples.append({
            "id": f"path_{i}",
            "language": "python",
            "vulnerability_type": "CWE-22: Path Traversal",
            "vulnerable_code": f"""def read_file(filename):
    with open(f"./uploads/{{filename}}", 'r') as f:
        return f.read()""",
            "fixed_code": f"""import os
def read_file(filename):
    safe_path = os.path.normpath(os.path.join("./uploads/", filename))
    if not safe_path.startswith(os.path.abspath("./uploads/")):
        raise ValueError("Invalid path")
    with open(safe_path, 'r') as f:
        return f.read()""",
            "description": "Path traversal vulnerability"
        })

    # Hardcoded credentials examples
    for i in range(10):
        samples.append({
            "id": f"creds_{i}",
            "language": "python",
            "vulnerability_type": "CWE-798: Hardcoded Credentials",
            "vulnerable_code": f"""def connect_db():
    password = "admin123"
    return db.connect("localhost", "admin", password)""",
            "fixed_code": f"""import os
def connect_db():
    password = os.environ.get("DB_PASSWORD")
    return db.connect("localhost", "admin", password)""",
            "description": "Hardcoded database credentials"
        })

    # Save manual dataset
    output_file = Path("data/manual_evaluation_samples.json")
    with open(output_file, 'w') as f:
        json.dump(samples, f, indent=2)

    print(f"Created manual dataset with {len(samples)} samples: {output_file}")
    return samples

if __name__ == "__main__":
    print("=" * 60)
    print("PatchGuard Dataset Preparation")
    print("=" * 60)

    # Try to download from Kaggle
    success = download_cvefixes_dataset()

    if success:
        # Prepare 500 samples
        prepare_500_samples()
    else:
        print("\nKaggle download failed. Using manual dataset instead.")
        print("To use Kaggle dataset:")
        print("1. Install: pip install kaggle")
        print("2. Get API token from: https://www.kaggle.com/settings")
        print("3. Place in: ~/.kaggle/kaggle.json")

        # Create manual dataset as fallback
        create_manual_dataset()

    print("\n" + "=" * 60)
    print("Dataset preparation complete!")
    print("=" * 60)
