"""
Terminal application for the Phishing URL Detection Tool.
"""

import csv
from pathlib import Path

from detector import analyze_url


CSV_FILE = Path(__file__).parent / "test_urls.csv"


def print_features(features):
    """Print extracted features in a readable format."""
    print("\nExtracted Features:")
    for feature_name, value in features.items():
        readable_name = feature_name.replace("_", " ").title()
        print(f"- {readable_name}: {value}")


def print_analysis(result):
    """Print the analysis result for one URL."""
    print("\nAnalysis Result")
    print("-" * 40)
    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['score']}")
    print(f"Risk Level: {result['risk_level']}")

    print("\nReasons:")
    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"- {reason}")
    else:
        print("- No risky indicators found")

    print_features(result["features"])


def analyze_single_url():
    """Ask the user for one URL and analyze it."""
    url = input("\nEnter a URL to analyze: ").strip()

    if not url:
        print("No URL entered. Please try again.")
        return

    result = analyze_url(url)
    print_analysis(result)


def test_urls_from_csv():
    """Read URLs from test_urls.csv and analyze each one."""
    try:
        with CSV_FILE.open("r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            print("\nCSV Test Results")
            print("-" * 80)
            print(f"{'Expected':<12} {'Predicted':<12} {'Score':<7} URL")
            print("-" * 80)

            for row in reader:
                url = row.get("url", "").strip()
                expected_label = row.get("label", "").strip()

                if not url:
                    continue

                result = analyze_url(url)
                print(
                    f"{expected_label:<12} "
                    f"{result['risk_level']:<12} "
                    f"{result['score']:<7} "
                    f"{url}"
                )

    except FileNotFoundError:
        print(f"\nError: Could not find {CSV_FILE.name}.")
        print("Please make sure test_urls.csv exists in the project folder.")


def show_menu():
    """Display the main menu."""
    print("\nPhishing URL Detection Tool")
    print("=" * 30)
    print("1. Analyze a single URL")
    print("2. Test URLs from CSV")
    print("3. Exit")


def main():
    """Run the terminal menu until the user exits."""
    while True:
        show_menu()
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            analyze_single_url()
        elif choice == "2":
            test_urls_from_csv()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
