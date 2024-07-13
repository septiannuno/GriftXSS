# GriftXSS

GriftXSS is a tool designed for automated scanning and detection of Cross-Site Scripting (XSS) vulnerabilities in web applications. Developed using Python, it aims to assist developers and security researchers in identifying and mitigating XSS vulnerabilities effectively.

## Key Features

- Automated scanning of various XSS injection points:
  - Headers
  - POST data
  - GET parameters
  - Cookies
  - URL fragments
  - DOM (Document Object Model)
  - Input forms
  - Web storage
  - JSON and JavaScript variables
  - Event handlers
  - HTML attributes
  - Third-party content
- WAF (Web Application Firewall) detection and bypass capabilities
- Automated risk assessment

## Installation

1. Ensure you have Python 3.7 or higher installed on your system. You can download Python from https://www.python.org/downloads/.

2. Clone the repository:
   git clone https://github.com/septiannuno/GriftXSS.git
   cd GriftXSS

3. Create a virtual environment (optional but recommended):
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`

4. Install the required dependencies:
   pip install -r requirements.txt

## Usage

To run GriftXSS, use the following command:

python griftxss.py -u <target_url> [option]

For example:
python griftxss.py https://example.com

For a list of available options, use:
python griftxss.py --help


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

GriftXSS is intended for educational and ethical testing purposes only. Always obtain proper authorization before scanning any web applications you do not own or have explicit permission to test.

## Contact

For questions, suggestions, or support, please open an issue on the GitHub repository or contact the maintainer at [senzdev1337@gmail.com].
