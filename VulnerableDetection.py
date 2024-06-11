class PhpCodeAnalyzer:
    def __init__(self):
        self.vulnerableFunctions = ['eval', 'include', 'require', 'mysqli_query', 'mysql_query', 'unserialize', 'exec', 'system', 'preg_replace', 'md5', 'sha1', 'htmlspecialchars', 'htmlentities']
        self.replacementFunctions = {
            'eval': 'filter_var($input, FILTER_VALIDATE_BOOLEAN)',
            'include': 'require_once($file)',
            'require': 'include_once($file)',
            'mysqli_query': '$mysqli->prepare($query)',
            'mysql_query': '$mysqli->query($query)',
            'unserialize': 'json_decode($input, true)',
            'exec': 'shell_exec($cmd)',
            'system': 'proc_open($cmd, $descriptorspec, $pipes)',
            'preg_replace': 'preg_replace_callback($pattern, $callback, $subject)',
            'md5': 'hash("sha256", $input)',
            'sha1': 'hash("sha256", $input)',
            'htmlspecialchars': 'htmlspecialchars($string, ENT_QUOTES | ENT_HTML5)',
            'htmlentities': 'htmlentities($string, ENT_QUOTES | ENT_HTML5)'
        }

    def readPhpCodeFile(self, file_path):
        phpCodeLines = []
        vulnerableFunctionsFound = []
        replacements = {}

        try:
            with open(file_path, 'r') as php_file:
                phpCodeLines = php_file.readlines()
                for lineNumber, line in enumerate(phpCodeLines, start=1):
                    for func in self.vulnerableFunctions:
                        if func in line:
                            vulnerableFunctionsFound.append(func)
                            replacements[func] = self.replacementFunctions.get(func, None)
            return phpCodeLines, vulnerableFunctionsFound, replacements
        except FileNotFoundError:
            print("File not found. Please provide a valid file path.")
            return [], [], {}

    def generateReport(self, phpCodeLines, vulnerableFunctions, outputFilePath):
        outputText = "VULNERABILITY FINDINGS REPORT\n\n"
        outputText += "PHP Code Lines:\n"
        for lineNumber, line in enumerate(phpCodeLines, start=1):
            outputText += f"Line {lineNumber}: {line.rstrip()}\n"  # rstrip() to remove trailing newline characters
        
        if vulnerableFunctions:
            outputText += "\nVulnerable Functions Found:\n"
            for func in vulnerableFunctions:
                outputText += func + "\n"
                if replacements[func]:
                    outputText += f"Possible Replacement: {replacements[func]}\n"
            outputText += "\nThe PHP code contains vulnerable functions.\n"
        else:
            outputText += "\nThe PHP code does not contain any vulnerable functions.\n"

        # Writing to a text file
        try:
            with open(outputFilePath, 'w') as outputFile:
                outputFile.write(outputText)
            print(f"Output written to '{outputFilePath}'")
        except FileNotFoundError:
            print("Output file path is invalid.")

# Usage
analyzer = PhpCodeAnalyzer()
file_path = input("Enter the path to the PHP file: ")
outputFilePath = input("Enter the output file path where the report is to be stored: ")
phpCodeLines, vulnerableFunctions, replacements = analyzer.readPhpCodeFile(file_path)

if phpCodeLines:
    analyzer.generateReport(phpCodeLines, vulnerableFunctions, outputFilePath)
else:
    print("PHP code not found or empty.")
