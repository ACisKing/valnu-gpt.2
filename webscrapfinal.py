import requests
from bs4 import BeautifulSoup
import psycopg2
from psycopg2 import sql

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

def connect_to_db():
    try:
        connection = psycopg2.connect(
            dbname="vuln",
            user="postgres",
            password="zanegone441",
            host="localhost",
            port="5432"
        )
        return connection
    except Exception as error:
        print(f"Error connecting to the database: {error}")
        return None

def create_table_if_not_exists(connection):
    try:
        cursor = connection.cursor()
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS cwe_cve_data (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255),
            cwe_cve_code VARCHAR(255) UNIQUE,
            description TEXT,
            detection_methods TEXT,
            mitigation_methods TEXT
        );
        '''
        cursor.execute(create_table_query)
        connection.commit()
        cursor.close()
    except Exception as error:
        print(f"Error creating table: {error}")

def insert_data_into_db(connection, data):
    try:
        cursor = connection.cursor()
        insert_query = sql.SQL('''
        INSERT INTO cwe_cve_data (name, cwe_cve_code, description, detection_methods, mitigation_methods)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (cwe_cve_code) DO NOTHING;
        ''')
        cursor.execute(insert_query, data)
        connection.commit()
        cursor.close()
    except Exception as error:
        print(f"Error inserting data: {error}")

def main():
    connection = connect_to_db()
    if not connection:
        return

    create_table_if_not_exists(connection)
    columns = ['Name', 'CWE/CVE Code', 'Description', 'Detection Methods', 'Mitigation Methods']

    while True:
        entry_id = input("Enter CWE or CVE ID (or 'exit' to quit): ").strip()
        if entry_id.lower() == 'exit':
            break

        if entry_id.upper().startswith('CWE-'):
            cwe_id = entry_id.split('-')[1]
            soup = fetch_cwe_data(cwe_id)
            if not soup:
                continue
            name = extract_cwe_name(soup)
            description = extract_section(soup, 'Description')
            detection_methods = extract_section(soup, 'Detection_Methods')
            mitigation_methods = extract_section(soup, 'Potential_Mitigations')
            data = (name, entry_id, description, detection_methods, mitigation_methods)
        elif entry_id.upper().startswith('CVE-'):
            cve_id = entry_id.split('-')[1]
            cve_data = fetch_cve_data(cve_id)
            if not cve_data:
                continue
            data = (
                cve_data["Name"],
                cve_data["CWE/CVE Code"],
                cve_data["Description"],
                cve_data["Detection Methods"],
                cve_data["Mitigation Methods"]
            )
        else:
            print("Invalid ID format. Please enter a valid CWE or CVE ID.")
            continue

        insert_data_into_db(connection, data)

    connection.close()

if __name__ == "__main__":
    main()
