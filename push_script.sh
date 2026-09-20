#!/bin/bash
# Push script for portscanner project

cd "C:/Users/Nathan/Projects/portscanner"
git init
git add .
git commit -m "Final project cleanup and documentation updates"
git remote add origin https://github.com/nbruce88/portscanner.git
git push -u origin master