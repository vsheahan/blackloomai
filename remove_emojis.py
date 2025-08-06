#!/usr/bin/env python3
"""
Remove all emojis and em dashes from BlackLoom Defense project files
"""

import os
import re
import glob
from pathlib import Path


class EmojiRemover:
 """Remove emojis and em dashes from project files"""

 def __init__(self, repo_root: str = "."):
 self.repo_root = Path(repo_root).resolve()
 self.modified_files = []

 # Common emoji patterns to remove
 self.emoji_patterns = [
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r'',
 r'', r'', r'', r'', r'', r'', r'', r''
 ]

 # Em dash and en dash patterns
 self.dash_patterns = [
 r'-', # em dash
 r'-', # en dash
 ]

 def process_all_files(self, dry_run: bool = False):
 """Process all Python and Markdown files"""
 print(f"Processing files in {self.repo_root}")
 if dry_run:
 print("DRY RUN MODE - No files will be modified")

 # Find all relevant files
 file_patterns = ['**/*.py', '**/*.md']
 all_files = []

 for pattern in file_patterns:
 all_files.extend(self.repo_root.glob(pattern))

 # Process each file
 for file_path in all_files:
 if self._should_skip_file(file_path):
 continue

 self._process_file(file_path, dry_run)

 # Summary
 print(f"\nSummary:")
 print(f"Files processed: {len(self.modified_files)}")
 if self.modified_files:
 print("Modified files:")
 for file_path in self.modified_files:
 print(f" - {file_path}")

 def _should_skip_file(self, file_path: Path) -> bool:
 """Check if file should be skipped"""
 skip_patterns = [
 '__pycache__',
 '.git',
 '.venv',
 'venv',
 'node_modules'
 ]

 path_str = str(file_path)
 for pattern in skip_patterns:
 if pattern in path_str:
 return True

 return False

 def _process_file(self, file_path: Path, dry_run: bool):
 """Process a single file"""
 try:
 with open(file_path, 'r', encoding='utf-8') as f:
 content = f.read()

 original_content = content

 # Remove emojis
 for emoji in self.emoji_patterns:
 content = re.sub(emoji, '', content)

 # Remove em dashes and en dashes, replace with regular hyphens
 for dash in self.dash_patterns:
 content = re.sub(dash, '-', content)

 # Clean up any double spaces or trailing spaces that might result
 content = re.sub(r' +', ' ', content) # Replace multiple spaces with single space
 content = re.sub(r' +\n', '\n', content) # Remove trailing spaces before newlines

 # Check if content changed
 if content != original_content:
 if dry_run:
 print(f"Would modify: {file_path.relative_to(self.repo_root)}")
 else:
 with open(file_path, 'w', encoding='utf-8') as f:
 f.write(content)
 self.modified_files.append(str(file_path.relative_to(self.repo_root)))
 print(f"Modified: {file_path.relative_to(self.repo_root)}")

 except Exception as e:
 print(f"Error processing {file_path}: {e}")

 def _clean_readme_badges(self, content: str) -> str:
 """Special handling for README badges with emojis"""

 # Replace emoji badges with clean versions
 badge_replacements = [
 # Navigation buttons
 (r'_Quick_Start', 'Quick_Start'),
 (r'_API_Docs', 'API_Documentation'),
 (r'_Live_Demo', 'Live_Demo'),

 # Section headers
 (r'## Core Security Components', '## Core Security Components'),
 (r'## OWASP ML Security Coverage', '## OWASP ML Security Coverage'),
 (r'## Quick Start', '## Quick Start'),
 (r'## Architecture', '## Architecture'),
 (r'## API Endpoints', '## API Endpoints'),
 (r'## Configuration', '## Configuration'),
 (r'## Security Features', '## Security Features'),
 (r'## Testing & Validation', '## Testing & Validation'),
 (r'## Monitoring & Analytics', '## Monitoring & Analytics'),
 (r'## Production Deployment', '## Production Deployment'),
 (r'## Use Cases', '## Use Cases'),
 (r'## Contributing', '## Contributing'),
 (r'## Resources & Research', '## Resources & Research'),
 (r'## License', '## License'),
 ]

 for old, new in badge_replacements:
 content = content.replace(old, new)

 return content

 def clean_specific_files(self, dry_run: bool = False):
 """Clean specific files with custom logic"""

 # README.md - special handling
 readme_path = self.repo_root / 'README.md'
 if readme_path.exists():
 print(f"Processing README.md with special handling...")

 with open(readme_path, 'r', encoding='utf-8') as f:
 content = f.read()

 original_content = content

 # Clean badges first
 content = self._clean_readme_badges(content)

 # Then remove remaining emojis
 for emoji in self.emoji_patterns:
 content = re.sub(emoji + r'\s*', '', content)

 # Clean up spacing
 content = re.sub(r'\n\n\n+', '\n\n', content) # Remove excessive newlines

 if content != original_content:
 if not dry_run:
 with open(readme_path, 'w', encoding='utf-8') as f:
 f.write(content)
 print("Modified README.md with special handling")
 else:
 print("Would modify README.md with special handling")


def main():
 """Main function"""
 import argparse

 parser = argparse.ArgumentParser(description="Remove emojis and em dashes from BlackLoom Defense project")
 parser.add_argument("--dry-run", action="store_true", help="Show what would be modified without actually modifying")
 parser.add_argument("--repo-root", default=".", help="Repository root directory")

 args = parser.parse_args()

 remover = EmojiRemover(args.repo_root)

 try:
 # First do special handling for specific files
 remover.clean_specific_files(dry_run=args.dry_run)

 # Then process all other files
 remover.process_all_files(dry_run=args.dry_run)

 print("\nEmoji and em dash removal completed!")

 except KeyboardInterrupt:
 print("\nOperation interrupted by user")
 return 1
 except Exception as e:
 print(f"Error: {e}")
 return 1

 return 0


if __name__ == "__main__":
 exit(main())