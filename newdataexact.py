import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

def fetch_cwe_data(cwe_id):
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup
    else:
        print(f"Error fetching CWE webpage: {response.status_code}")
        return None

def extract_section(soup, section_id):
    section = soup.find(id=section_id)
    if section:
        return section.get_text(strip=True)
    else:
        return "Not Available"

def extract_cwe_name(soup):
    title = soup.find('h2')
    if title:
        return title.get_text(strip=True)
    else:
        return "Not Available"

def fetch_cve_data(cve_id):
    url = f"https://www.cvedetails.com/cve/CVE-{cve_id}/"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        description = soup.find('div', {'class': 'cvedetailssummary'}).get_text(strip=True) if soup.find('div', {'class': 'cvedetailssummary'}) else "Not Available"
        return {
            "Name": f"CVE-{cve_id}",
            "CWE/CVE Code": f"CVE-{cve_id}",
            "Description": description,
            "Detection Methods": "Not Available",
            "Mitigation Methods": "Not Available"
        }
    else:
        print(f"Error fetching CVE webpage: {response.status_code}")
        return None

def append_to_excel(data, filename):
    if os.path.exists(filename):
        existing_data = pd.read_excel(filename)
        existing_ids = existing_data['CWE/CVE Code'].tolist()
        
        # Filter out any entries that are already in the existing data
        new_data = data[~data['CWE/CVE Code'].isin(existing_ids)]
        if not new_data.empty:
            data = pd.concat([existing_data, new_data], ignore_index=True)
        else:
            print(f"ID {data['CWE/CVE Code'].iloc[0]} already exists in the sheet.")
            return
    else:
        data = data

    with pd.ExcelWriter(filename, engine='openpyxl', mode='w') as writer:
        data.to_excel(writer, index=False)
    print(f"Data appended to '{filename}'")

def main():
    downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    filename = os.path.join(downloads_path, 'cwe_cve_data.xlsx')
    columns = ['Name', 'CWE/CVE Code', 'Description', 'Detection Methods', 'Mitigation Methods']

    range_start = int(input("Enter the start of the range (inclusive): ").strip())
    range_end = int(input("Enter the end of the range (inclusive): ").strip())

    for entry_id in range(range_start, range_end + 1):
        cwe_id = str(entry_id)
        soup = fetch_cwe_data(cwe_id)
        if not soup:
            continue
        name = extract_cwe_name(soup)
        description = extract_section(soup, 'Description')
        detection_methods = extract_section(soup, 'Detection_Methods')
        mitigation_methods = extract_section(soup, 'Potential_Mitigations')
        data = pd.DataFrame([[name, f"CWE-{cwe_id}", description, detection_methods, mitigation_methods]], columns=columns)
        append_to_excel(data, filename)

if __name__ == "__main__":
    main()
