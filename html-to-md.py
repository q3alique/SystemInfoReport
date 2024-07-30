import argparse
from bs4 import BeautifulSoup
import markdownify as md
import os
import chardet

# Set up argument parsing
parser = argparse.ArgumentParser(description='Convert HTML to Markdown.')
parser.add_argument('-f', '--file', required=True, help='Input HTML file')
args = parser.parse_args()

# Input and output file paths
html_file = args.file
base_name = os.path.splitext(html_file)[0]
markdown_file = f"{base_name}.md"

# Detect the file encoding
with open(html_file, 'rb') as f:
    raw_data = f.read()
    result = chardet.detect(raw_data)
    encoding = result['encoding']

# Read the HTML file with the detected encoding
with open(html_file, 'r', encoding=encoding) as f:
    html_content = f.read()

# Parse the HTML content using BeautifulSoup
soup = BeautifulSoup(html_content, 'html.parser')

# Convert the parsed HTML content into Markdown
# Adjust the header levels and minimize the space
markdown_content = md.markdownify(str(soup), heading_style="ATX")

# Adjust headers and spacing manually
markdown_content = markdown_content.replace('# ', '### ').replace('## Enhanced System Information Report', '## Enhanced System Information Report')
markdown_content = '\n'.join(line.strip() for line in markdown_content.splitlines() if line.strip())

# Write the Markdown content to a file
with open(markdown_file, 'w', encoding='utf-8') as f:
    f.write(markdown_content)

print(f"Markdown file '{markdown_file}' has been created successfully.")
