import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import logging
from openai import OpenAI

logger = logging.getLogger(__name__)

DEFAULT_SERVER = 'http://127.0.0.1:8000'

# OpenAI settings
OPENAI_API_KEY = 'OPENAI_API_KEY HERE'

openai_client = OpenAI(api_key=OPENAI_API_KEY)

class MobSF:
    """Represents a MobSF instance."""

    def __init__(self, apikey, server=None):
        self.__server = server.rstrip('/') if server else DEFAULT_SERVER
        self.__apikey = apikey

    @property
    def server(self):
        return self.__server

    @property
    def apikey(self):
        return self.__apikey

    def upload(self, file):
        """Upload an app."""
        logger.debug(f"Uploading {file} to {self.__server}")
        multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': self.__apikey}
        r = requests.post(f'{self.__server}/api/v1/upload', data=multipart_data, headers=headers)
        return r.json()

    def scan(self, scantype, filename, scanhash, rescan=False):
        """Scan already uploaded file."""
        logger.debug(f"Requesting {self.__server} to scan {scanhash} ({filename}, {scantype})")
        post_dict = {'scan_type': scantype, 'file_name': filename, 'hash': scanhash, 're_scan': rescan}
        headers = {'Authorization': self.__apikey}
        r = requests.post(f'{self.__server}/api/v1/scan', data=post_dict, headers=headers)
        return r.json()

    def scans(self, page=1, page_size=100):
        """Show recent scans."""
        logger.debug(f'Requesting recent scans from {self.__server}')
        payload = {'page': page, 'page_size': page_size}
        headers = {'Authorization': self.__apikey}
        r = requests.get(f'{self.__server}/api/v1/scans', params=payload, headers=headers)
        return r.json()

    def report_pdf(self, scanhash, pdfname=None):
        """Retrieve and store a scan report as PDF."""
        pdfname = pdfname if pdfname else 'report.pdf'
        logger.debug(f'Requesting PDF report for scan {scanhash}')
        headers = {'Authorization': self.__apikey}
        data = {'hash': scanhash}
        r = requests.post(f'{self.__server}/api/v1/download_pdf', data=data, headers=headers, stream=True)
        logger.debug(f'Writing PDF report to {pdfname}')
        with open(pdfname, 'wb') as pdf:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    pdf.write(chunk)
        logger.info(f'Report saved as {pdfname}')
        return pdfname

    def report_json(self, scanhash):
        """Retrieve JSON report of a scan."""
        logger.debug(f'Requesting JSON report for scan {scanhash}')
        headers = {'Authorization': self.__apikey}
        data = {'hash': scanhash}
        r = requests.post(f'{self.__server}/api/v1/report_json', data=data, headers=headers)
        return r.json()

    def view_source(self, scantype, filename, scanhash):
        """Retrieve source files of a scan."""
        logger.debug(f'Requesting source files for {scanhash} ({filename}, {scantype})')
        headers = {'Authorization': self.__apikey}
        data = {'type': scantype, 'hash': scanhash, 'file': filename}
        r = requests.post(f'{self.__server}/api/v1/view_source', data=data, headers=headers)
        return r.json()

    def delete_scan(self, scanhash):
        """Delete a scan result."""
        logger.debug(f'Requesting {self.__server} to delete scan {scanhash}')
        headers = {'Authorization': self.__apikey}
        data = {'hash': scanhash}
        r = requests.post(f'{self.__server}/api/v1/delete_scan', data=data, headers=headers)
        return r.json()

    def analyze_findings_with_openai(self, findings_summary):
        """Analyze the findings summary using OpenAI."""
        prompt_text = f"""You are an AI assistant with advanced expertise in cybersecurity, specifically tailored towards the intricacies of mobile application security as per the OWASP Mobile Application Security Verification Standard (MASVS). Your mission involves a deep dive into the provided text, employing a meticulous and methodical approach to uncover and elucidate vulnerabilities. Your analysis should not only uncover and categorize critical security flaws in line with the distinct categories outlined by MASVS but also delve into the underlying causes and potential impact of these issues on the mobile application's overall security posture.
        In your exploration, prioritize clarity and accessibility in your explanations, ensuring that both technical and non-technical stakeholders can grasp the significance of the findings. For each identified vulnerability, classify it according to the relevant MASVS category, and elaborate on why it constitutes a security risk within the mobile application context. Your recommendations for mitigation should be practical, actionable, and tailored to the nuances of mobile app development, considering both the immediate steps for remediation and long-term strategies for enhancing security resilience.
        Moreover, your analysis should integrate a holistic view of mobile security, taking into account the broader ecosystem including but not limited to, data transmission security, user authentication mechanisms, and third-party service integrations. Highlight any observed deviations from MASVS guidelines, and propose a roadmap for aligning the application more closely with these standards.
        In summary, your task is to provide a comprehensive, insightful, and accessible analysis of the vulnerabilities present in the mobile application, guided by MASVS. Your goal is to empower developers and security professionals with the knowledge and strategies necessary to fortify their mobile applications against both current and emerging security threats.\n\n""" + findings_summary[:4000]  # Adjust the length as needed to ensure focus and clarity.

        try:
            response = openai_client.chat.completions.create(
                model="gpt-4",  # Updated to the correct method
                messages=[
                    {
                     "role": "system",
                     "content": "You are an AI trained in mobile application security analysis following OWASP MASVS guidelines."
                    },
                    {
                     "role": "user",
                     "content": prompt_text
                    }
                ]
            )
            
            if response.choices and response.choices[0].message:
                analysis = response.choices[0].message.content.strip()
            else:
                analysis = "Analysis not found in the response."
            logger.info("Analysis complete.")
            return analysis
        except Exception as e:
            logger.error(f"Error during OpenAI analysis: {e}")
            return None
