import requests
import time
import base64

API_KEY = "<MY VIRUSTOTAL API KEY :))>"
VT_API = "https://www.virustotal.com/api/v3"  # VirusTotal API base URL

def get_url_id(url):
    # VirusTotal expects base64 URL without padding for lookups
    url_bytes = url.encode('utf-8')
    url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip("=")
    return url_id

def submit_and_fetch_report(target_url):
    # Step 1: Submit the URL for a scan (rate: 4 requests/min allowed)
    scan_url = f"{VT_API}/urls"
    headers = {
        'x-apikey': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = f"url={target_url}"
    response = requests.post(scan_url, headers=headers, data=data)
    response.raise_for_status()
    scan_id = response.json()['data']['id']

    # Respect public rate limiting: e.g., wait between requests if batching
    time.sleep(16)  # 4 requests/minute limit

    # Step 2: Fetch extremely detailed report using the scan ID
    report_url = f"{VT_API}/analyses/{scan_id}"
    headers = {'x-apikey': API_KEY}
    report_response = requests.get(report_url, headers=headers)
    report_response.raise_for_status()
    full_report = report_response.json()

    # Step 3: Deep-dive by fetching extra information from the URL's unique identifier
    url_id = get_url_id(target_url)
    full_url_info = requests.get(f"{VT_API}/urls/{url_id}", headers=headers)
    full_url_info.raise_for_status()
    url_details = full_url_info.json()

    # Suggested data points to extract for a detailed report
    analysis_stats = url_details.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    scan_engines = url_details.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    community_votes = url_details.get('data', {}).get('attributes', {}).get('votes', {})
    reputation = url_details.get('data', {}).get('attributes', {}).get('reputation', {})
    tags = url_details.get('data', {}).get('attributes', {}).get('tags', [])

    # Example: Print key info (extend as desired)
    print("\nVirusTotal Analysis Report")
    print(f"Target URL: {target_url}")
    print("Analysis stats:", analysis_stats)
    print("Reputation:", reputation)
    print("Community votes:", community_votes)
    print("Tags:", tags)
    print("\nScan engine verdicts:")
    for engine, details in scan_engines.items():
        print(f"{engine}: {details['category']} - {details['result']}")

    # Full raw details are available in url_details and full_report for advanced analysis.

if __name__ == "__main__":
    # Replace with your URL
    url_to_check = "https://micros0ft.com"
    submit_and_fetch_report(url_to_check)
