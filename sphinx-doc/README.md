# MFD OSD Control SPHINX DOCUMENTATION

## HOW TO GENERATE DOCS
### 1. Download or use system embedded Python in version at least 3.7
### 2. Create venv
- Create Python venv from MFD OSD Control requirements for Sphinx (`<mfd_osd_control_folder>/requirements-docs.txt`) 
- Link how to do this: `https://python.land/virtual-environments/virtualenv`
### 3. In Activated venv go to MFD OSD Control directory `<mfd_osd_control_folder>/sphinx-doc`
### 4. Run command:
```shell
$ python generate_docs.py
```
### 5. Open `<mfd_osd_control_folder>/sphinx-doc/build/html/index.html` in Web browser to read documentation