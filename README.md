# Does This Dependency Matter

This is the artifact repo for our paper: Does This Dependency Matter by Eldon Lake and Ridwan Andalib.
In order to make replicating the results easier, this is a fork of the vscode-codeql starter workspace.
While our runtime benchmarks were created with the CodeQL CLI, we recommend using vscode when running
the queries, because it provides a more intuitive way to inspect and interpret the results.

# Paper

The final draft of our paper can be found here: [Link](https://raw.githubusercontent.com/elake/dtdm/master/DTDM.pdf)
Please ignore the conference date in the header, it was included to match the requested spec but this paper has not
been peer reviewed or submitted for publication.

# Instructions

## vs code & extension installation:
1. Install [Visual Studio Code](https://code.visualstudio.com).
1. Install the [CodeQL extension for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=github.vscode-codeql).
1. Clone this repository to your computer.
    - Make sure to include the submodules, either by `git clone --recursive` or by `git submodule update --init --remote` after clone.
1. In VS Code, click File > Open Workspace. Select the file `vscode-codeql-starter.code-workspace` in your checkout of this repository.
1. The folder named `codeql-custom-queries-python` contains the DDTM queries
1. Follow the [documentation for the CodeQL extension](https://help.semmle.com/codeql/codeql-for-vscode.html) for instruction on setting up the extension, adding a database and running queries

## DTDM Queries
Once you have cloned this repo and completed the vscode and codeql extension installations,
you can use our queries to analyze any CodeQL database created from a Python source, exactly
the same as you would any other query. The query files can be found in /codeql-custom-queries-python/
If a query returns any results on a project, it is considered vulnerable by DTDM. If a query returns no
results on a project, it is considered safe by DTDM. This should be all you need to replicate the results
of our experiment.

## Real World Tests
The databases for the tests exceeded GitHub file size limits. You can find a zip file for them here:
https://drive.google.com/file/d/1I9eQ1tkPYpEHsDtyKXUdNYtbtvCBUtgs/view?usp=sharing
This zip file includes the original repos, the CodeQL databases generated from each repo, and the
Windows batch files that were used to time the results for queries. We recommend using vscode to
test the queries, instead of the batch files. Should you choose to use them, the batch files must
be edited to match your directory structure and choice of database / query combination, and require
the CodeQL CLI (see below).

## Artificial Tests
The databases for the artifical tests include src.zip files with the source code as well. The batch
files here, similar to the ones above, are for Windows and require the CLI. Again, you will have to
replace the directories in the files with your own directories, should you choose to use them. Again, 
will likely find it easier to use vscode instead. The artifical tests can be found in this zip file:
https://drive.google.com/file/d/1_yLupJxM3UZV_SE6KXUif69qLixJknLe/view?usp=sharing

## CLI for Testing Runtimes (required for batch)
The Windows batch files we used to measure our query runtimes did not use vs code, and instead ran
using the CodeQL CLI. Instruction for installing the CLI can be found here:
https://help.semmle.com/codeql/codeql-cli/procedures/get-started.html

This syntax in your terminal should get you going, once you have the CLI in your path:

codeql database analyze "path to db folder" "path to query file" --format=csv --output="path to output file"
    
This may throw an error when running a path problem such as taint analysis, in which can you can try:

codeql query run --database="path to db folder" --output="path to results file" "path to query file"

Alteratively, you may follow these instructions:
https://help.semmle.com/codeql/codeql-cli/procedures/analyze-codeql-database.html
Or simply copy terminal commands out of the batch files. 

## CLI Notes
The results file created by the CLI has occasionally given us garbled output on Windows. While it doesn't seem
to affect the runtime in these cases, it's worth noting. If you decided to use the CLI to perform queries
and encounter this error, running them in vscode has always worked for us regardless of our environment.
Swapping between "codeql database analyze" and "codeql query run" can also help when this happens.

## Virtual Machine
This virtual machine has everyting preinstalled on Ubuntu including the test repositories, to help make
it easier to reproduce our results:
https://drive.google.com/drive/folders/1yc0bXcycevIa26jvV8BEbI0n93Pla-8T?usp=sharing

## Credit
This repo is a fork of the vscode-codeql starter workspace. The original license is included below.
## License

This project is [licensed](LICENSE.md) under the MIT License. 

The CodeQL extension for Visual Studio Code is [licensed](https://github.com/github/vscode-codeql/blob/master/extensions/ql-vscode/LICENSE.md) under the MIT License. The version of CodeQL used by the CodeQL extension is subject to the [GitHub CodeQL Terms & Conditions](https://securitylab.github.com/tools/codeql/license).
