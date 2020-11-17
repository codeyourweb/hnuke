
# Hash parser and VirusTotal analysis with both VT free and entreprise API  

## History

This project was born on a rainy Saturday when Casey Brooks (a.k.a @DrunkBinary), posted a lot of tweets with hashs related to Turla APT. I would like to do some analysis on them but  but i couldn't affort a VT Entreprise licence. I then thought that the lack of money didn't mean that I had to do everything by hand and that maybe some things could be done entirely with free API. 

With this sole motivation in mind, this little handy tool was born. It's not design to change the world of cybersecurity, but it helped me a lot during my APT hunting, and maybe  someday it will save your time too :)

### Key features
* Parse md5/sha1/sha256 from your input path and search them on VirusTotal 
* Extract usefull informations from VT API to help you decide whether theses items are harmull or not and if there are some elements to pivot on.
* Remove duplicate content before output
* Includes a time delay when the API call limit is reached
* Direct analysis mode embeded to calculate hash of provided content (local and distant file) that could be usefull in a triage mode
* If you want to stop the routine in progress, CTRL+C save and quit to not loose any work when this is no longer possible today

## Capababilities and use cases

Hnuke was designed for two purpose:
* **Parser mode:** based on a file, a path or an URL,  search for every md5 / sha1 or sha256 hash and load usefull informations that help you decided if it's harmfull or not. Then it shows any relevant information (footprint, fuzzyhash, first submission, tag, details...) on what you can pivot on.  
* **Analysis mode:** similar to parser mode, except that instead of searching for hash it will get your input sha1 and will search it on VIrusTotal (don't worry, it won't submit your files :)

### Usage examples

The more simple way to use hnuke is:

    hnuke -a [apikey] -i [file / directory or url]   

You can use recursive mode if you want this tool parsing every subfolder

    hnuke -a [apikey] -i [directory] -r

If you need to know if a distant file is present on VirusTotal without putting it on your disk: 

    hnuke -a [apikey] -i [url] -r -m analysis

If you want to scan every *.exe and *.dll on a specified path, calculate their hashs and search them on VT: 

    hnuke -a [apikey] -i [directory] -r -m analysis -e .exe -e .dll

#### Commands details

    hnuke [-h|--help] -a|--apikey "<value>" -i|--in "<value>" [-o|--out
                 "<value>"] [-f|--format "<value>"] [-m|--mode "<value>"]
                 [-r|--recursive] [-e|--extension "<value>" [-e|--extension
                 "<value>" ...]]
    
    
    Arguments:
      -h  --help       Print help information
      -a  --apikey     VirusTotal API Key
      -i  --in         Input file or directory
      -o  --out        Save results to specified file - if not mentioned results
                       will be printed to standard output
      -f  --format     Output format - csv | json supported. Default: csv
      -m  --mode       hnuke mode (parser / analysis)
    
    parser : scan for md5/sha1/sha256 hash inside provided input file or directory
    analysis : get hash of provided input file or directory and search them in VirusTotal.  
    Default: parser
    
    -r  --recursive If input path is a directory, scan for files recursively (works with both parser and analysis mode)
      -e  --extension  If input path is a directory, include specified file extension (can be used multiple time)


### Input / Output
The parser mode can handle every text or PDF based file. It is also capable of crawling an HTML web page based on an URL. You can use a path as input and even ask hnuke to crawl file recursively. 

The current output formats are CSV and JSON, whether in a file or in the standard output of the application.
 
An example of input file and associated results are available in the examples folder of this repository. 


## Installation

Compiled executables are available for both Windows and Linux platform in the release section of this repository. You can alson use go get if you want to run the application from source code.

## Known bugs
* PDF parsing (currently some hashs are not seen correctly) 
* PDF can't be opened in parsing mode on some documents (don't really know why, i'm currently investigating on this)
* HTML content: the webpages are converted to text before parsing, when there is a lot of nested div, theses hashs seems truncated and thus not recognized by hnuke


## What's next?

It will depend on my needs and, if this tool could be usefull for the community, your expectations. This project has been made in few days, so there must be hundreds of other possibilities ;) Feel free to submit some features requests or add yours with a PR.

## Additional informations

Examples of hnuke processing available in "examples" folder. are based on public OSINT reports or tweets (TLP:WHITE). 




