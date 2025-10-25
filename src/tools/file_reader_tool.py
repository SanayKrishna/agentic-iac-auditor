# src/tools/file_reader_tool.py

import os
from crewai_tools import BaseTool

class FileReaderTool(BaseTool):
    name: str = "File Reader Tool"
    description: str = "Reads the content of a specified file. Use this to inspect IaC code."

    def _run(self, file_path: str) -> str:
        try:
            if not os.path.exists(file_path):
                return f"Error: File '{file_path}' does not exist."
            if not os.path.isfile(file_path):
                return f"Error: Path '{file_path}' is not a file."

            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"Unexpected error reading file: {str(e)}"

# Instantiate the tool
file_reader_tool = FileReaderTool()
